from flask import Flask, request, jsonify, abort, Response, g
import threading
import time
import sys
import os
import socket
import hashlib
import requests
import logging
import json
from markupsafe import escape
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Literal, TypedDict, Protocol
import time


logging.basicConfig(level=logging.INFO)

REQUEST_TIMEOUT = (2,5)

@dataclass
class NodeInfo:
    '''Node encapsulator'''
    hostname: str
    port: int
    nodeID: int

def getShaHash(value:str, ringSize: int) -> int:
    hash = int(hashlib.sha1(value.encode("utf-8")).hexdigest(), 16)
    return hash % ringSize

def shutdown_after(ttl: int):
    '''Force terminate program after given time'''
    time.sleep(ttl)
    print("Shutting down")
    os._exit(0)

class Node:
    def __init__(self, hostName: str, port: int, m: int, ringSize: int):
        completeHostname = f"{hostName}{port}"
        hash = getShaHash(completeHostname, ringSize)
        print("hash: " +str(hash))
        
        self.nodeInfo: NodeInfo = NodeInfo(hostname, port, hash)

        self.m = m
        self.ringSize = ringSize
        self.successor = None
        self.predecessor = None
        self.finger: list[NodeInfo] = [NodeInfo(hostname, port, hash) for _ in range(m)]
        self.printNodes()
        self.data = {}

    def createRing(self):
        #self.predecessor = None

        self.successor = self.nodeInfo

        # Initiate finger table with only me
        print("len: " + str(len(self.finger)))
        for i in range(self.m):
            self.finger[i] = self.nodeInfo
            
        self.printNodes()

    def printNodes(self):
            for i in self.finger:
                print(str(i.hostname) + " " + str(i.port) + " " + str(i.nodeID))
    
    def joinRing(self, contactNode: NodeInfo):
        # Find who my successor is by asking any given node
        self.successor = self.getRemoteSuccessor(contactNode, self.nodeInfo.nodeID)

        pred = self.getRemotePredecessor(self.successor)  # may be None
        if pred is None:
            # two-node ring: predecessor is the only other node (my successor)
            self.predecessor = self.successor
        elif self.isWithinInterval(self.nodeInfo.nodeID, pred.nodeID, self.successor.nodeID):
            self.predecessor = pred
        else:
            # rare race / inconsistent view: fall back to successor
            self.predecessor = self.successor

        # Populate finger table by querying the ring for informaiton
        for i in range(self.m):
            start = (self.nodeInfo.nodeID + (2 ** i)) % self.ringSize
            self.finger[i] = self.findSuccessor(start)

        # Inform successor I am potentially new predecessor
        self.notifySuccessor()

        try:
            # Ask successor to update (stabalise)
            self.rpcPost(self.successor, "/update", {})
            # Get successor's predecessor
            # resp = self.rpcGet(self.successor, "/get_pedecessor")
            # pred = resp.get("predecessor")
            pred = self.getRemotePredecessor(self.successor)
            if pred:
                self.rpcPost(pred, "/update", {})  
        except:
            pass
        
        self.buildFingerTable()
        self.rpcPost(self.successor, "/repair_hand", {})

        self.notify_entire_ring(True)

    def notify_entire_ring(self, do_fix_fingers: bool = True, hop_cap: Optional[int] = None):
        """
        Walk the ring via successors, once, calling /update and /repair_hand.
        """

        cap = hop_cap if hop_cap is not None else (2 ** self.m + 1)
        visited = set()
        steps = 0

        curr = self.successor
        if curr is None:
            return {"visited": [], "steps": 0}

        while curr and (curr.hostname, curr.port) not in visited and steps < cap:
            visited.add((curr.hostname, curr.port))

            # ask node to update once
            try:
                self.rpcPost(curr, "/update", {})
            except Exception:
                pass

            # ask node to rebuild its finger table once (if you exposed it)
            if do_fix_fingers:
                try:
                    self.rpcPost(curr, "/repair_hand", {})
                except Exception:
                    pass

            # move to its successor
            try:
                st = self.rpcGet(curr, "/state")
                nxt = st.get("successor")
                if not nxt:
                    break
                curr = NodeInfo(nxt["hostname"], int(nxt["port"]), int(nxt["nodeID"]))
            except Exception:
                break

            steps += 1

            # stop once Im back 
            if (curr.hostname, curr.port) == (self.nodeInfo.hostname, self.nodeInfo.port):
                break

        return {"visited": [f"{h}:{p}" for (h, p) in visited], "steps": steps}

    def walk_ring(self, hop_cap: Optional[int] = None) -> list[NodeInfo]:
        """
        Follow successor pointers around until i get back or hit cap
        """
        cap = hop_cap if hop_cap is not None else (2 ** self.m + 1)
        visited = set()
        nodes: list[NodeInfo] = []
        curr = NodeInfo(self.nodeInfo.hostname, self.nodeInfo.port, self.nodeInfo.nodeID)
        steps = 0

        while curr and (curr.hostname, curr.port) not in visited and steps < cap:
            nodes.append(curr)
            visited.add((curr.hostname, curr.port))
            try:
                st = self.rpcGet(curr, "/state") 
                succ = st.get("successor")
                if not succ:
                    break
                curr = NodeInfo(succ["hostname"], int(succ["port"]), int(succ["nodeID"]))
            except Exception:
                break
            steps += 1

        return nodes

    def get_all_hosts_json(self) -> List[str]:
        """
        Return a JSON-serializable list of node addresses ("host:port") for /network.
        """
        nodes = self.walk_ring()
        addresses = [f"{n.hostname}:{n.port}" for n in nodes]
        return addresses

    def notifySuccessor(self):
        self.rpcPost(self.successor, "/notify", {"hostname": self.nodeInfo.hostname, "port": self.nodeInfo.port, "id": self.nodeInfo.nodeID})
    
    def buildFingerTable(self):
        newFingers = []
        for i in range(self.m):
            start = (self.nodeInfo.nodeID + (2 ** i)) % ringSize
            newFingers.append(self.findSuccessor(start))
        self.finger = newFingers

    def getRemotePredecessor(self, contactNode: NodeInfo) -> Optional[NodeInfo]:
        resp = self.rpcGet(contactNode, "/get_predecessor", params={})
        data = resp.get("predecessor")
        if not data:
            return None
        return NodeInfo(data["hostname"], data["port"], data["nodeID"])
  
    
    def getRemoteSuccessor(self, contactNode: NodeInfo, targetID: int) -> NodeInfo:
        data = self.rpcGet(contactNode, "/find_successor", params={"id": targetID})
        return NodeInfo(data["hostname"], data["port"], data["nodeID"])
    
    def updateSelf(self):
        '''Update oneself if hit by a notification'''        
        if self.successor.nodeID == self.nodeInfo.nodeID:
            self.successor = self.findSuccessor(self.nodeInfo.nodeID)
        print("succ: " +str(self.successor))

    def iAmOwner(self, targetID) -> bool:
        '''Checks if the given identifier is this node, or between this node and the predecessor'''
        # Normal mode
        if self.predecessor.nodeID < self.nodeInfo.nodeID:
            return self.predecessor.nodeID < targetID <= self.nodeInfo.nodeID
        # Wrap-around mode
        if self.predecessor.nodeID > self.nodeInfo.nodeID:
            return targetID > self.predecessor.nodeID or targetID <= self.nodeInfo.nodeID
        # If it is not in here
        return False

    def isWithinInterval(self, targetID: int, startID: int, endID: int) -> bool:
        '''Checks if the the given identifier is within the given start and end interval'''
        # Normal mode
        if startID < endID:
            return startID < targetID < endID
        # Wrap-around mode
        if startID > endID:
            return targetID > startID or targetID < endID
        return False

    def getClosestPreceedingNode(self, targetID: int) -> NodeInfo:
        '''Go through the finger table from highest to lowest ID, find the first (closest) preceeding node for the target identifier'''
        for i in range(self.m -1, -1 ,-1 ):
            fingerNode = self.finger[i]
            if self.isWithinInterval(fingerNode.nodeID, self.nodeInfo.nodeID, targetID):
                return fingerNode
        # If no one was found this node is the closest
        #return self.successor
        return self.nodeInfo
    
    def isSuccessorOwner(self, targetID: int) -> bool:
        ''' Check if target is between this node and successor node or is on the successor node'''
        #Normal mode
        if self.nodeInfo.nodeID < self.successor.nodeID:
            return self.nodeInfo.nodeID < targetID <= self.successor.nodeID
        # Wrap-around mode
        if self.nodeInfo.nodeID > self.successor.nodeID:
            return targetID > self.nodeInfo.nodeID or targetID <= self.successor.nodeID
        # If no one was found 
        return False

    def findSuccessor(self, targetID: int) -> NodeInfo:
        # Check if successor is owner
        if self.isSuccessorOwner(targetID):
            #return self.nodeInfo
            return self.successor
        # Check if I am owner
        elif self.nodeInfo.nodeID == self.successor.nodeID:
            return self.nodeInfo
        # Check finger table for closest preceeding node
        fingerNode: NodeInfo = self.getClosestPreceedingNode(targetID)
        # Check if I am alone
        if (fingerNode.hostname == self.nodeInfo.hostname):
            return self.getRemoteSuccessor(self.successor, targetID)
            #return self.nodeInfo
        return self.getRemoteSuccessor(fingerNode, targetID)

    def storeValue(self, key, value):
        keyID = getShaHash(key, self.ringSize)
        owner = self.findSuccessor(key)
        # Check if I am the owner
        if (owner.hostname == self.nodeInfo.hostname) and (owner.port == self.nodeInfo.port):
            self.data[keyID] = value
            return True
        else:
            url = f"http://{owner.hostname}:{owner.port}/storage/{key}"
            try:
                resp = requests.put(url, "/storage/{keyID}", timeout=REQUEST_TIMEOUT)
                return resp.ok
            except:
                return False
        
    def getValue(self, key):
        keyID = getShaHash(key, self.ringSize)
        owner = self.findSuccessor(keyID)
        if (owner.hostname == self.nodeInfo.hostname) and (owner.port == self.nodeInfo.port):
            value = self.data.get(keyID)
            return value
        else:
            url = f"http://{owner.hostname}:{owner.port}/storage/{key}"
            try:
                resp = requests.get(url,timeout=REQUEST_TIMEOUT)
                if resp.status_code == 200:
                    return resp.text
                else:
                    return None
            except:
                return None
        
    # -------------- RPC --------------

    def rpcGet(self, contactNode: NodeInfo, path: str, params=None):
        base: str = "http://"+ str(contactNode.hostname) + ":" + str(contactNode.port)
        url = f"{base}{path}"
        print("contacting: " + str(url))
        result = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        result.raise_for_status()
        return result.json()

    def rpcPost(self, contactNode: NodeInfo, path: str, json_body=None):
        base: str = "http://"+ str(contactNode.hostname) + ":" + str(contactNode.port)
        url = f"{base}{path}"
        result = requests.post(url, json=json_body, timeout=REQUEST_TIMEOUT)
        result.raise_for_status()
        return result.json() if result.content else {}
    
    def rpcPut(self, contactNode: NodeInfo, path: str, json_body=None):
        base: str = "http://"+ str(contactNode.hostname) + ":" + str(contactNode.port)
        url = f"{base}{path}"
        result = requests.put(url, json=json_body, timeout=REQUEST_TIMEOUT)
        result.raise_for_status()
        return result.json() if result.content else {}
    
    # -------------- API --------------
    
    def setupRoutes(self):
        app = Flask(__name__)
        node: Node = self

        @app.route('/helloworld')
        def helloworld():
            return str(self.nodeInfo.hostname) + ":" + str(self.nodeInfo.port)

        @app.get("/id")
        def http_id():
            return jsonify({"hostname": node.nodeInfo.hostname, "port": node.nodeInfo.port, "id": node.nodeInfo.nodeID})
        
        @app.get("/state")
        def http_state():
            return jsonify({
                "self": {"hostname": node.nodeInfo.hostname, "port": node.nodeInfo.port, "id": node.nodeInfo.nodeID},
                "predecessor": asdict(node.predecessor) if node.predecessor else None,
                "successor": asdict(node.successor) if node.successor else None,
                "fingers": [asdict(f) for f in node.finger],
                #"kv_size": len(node.store),
                "m_bits": node.m,
                "ringSize" : node.ringSize
            })
        @app.get("/status")
        def http_status():
            #node.buildFingerTable()
            data = {
                "self": {
                    "hostname": node.nodeInfo.hostname,
                    "port": node.nodeInfo.port,
                    "id": node.nodeInfo.nodeID,
                },
                "predecessor": asdict(node.predecessor) if node.predecessor else None,
                "successor": asdict(node.successor) if node.successor else None,
                "fingers": [asdict(f) for f in node.finger],
                # "kv_size": len(node.store),
                "m_bits": node.m,
                "ringSize" : node.ringSize
            }

            html = f"""<!doctype html>
        <html>
        <head><meta charset="utf-8"><title>Node Status</title></head>
        <body>
        <h1>Node Status</h1>
        <pre>{escape(json.dumps(data, indent=2))}</pre>
        </body>
        </html>"""

            return Response(html, mimetype="text/html")

        @app.route('/find_successor')
        def httpFindSuccessor():
            targetID = int(request.args["id"])
            successor = node.findSuccessor(targetID)
            return jsonify(asdict(successor))
        
        @app.get("/get_predecessor")
        def http_get_predecessor():
            if node.predecessor is None:
                return jsonify({"predecessor": None})
            return jsonify({"predecessor": asdict(node.predecessor)})
        
        @app.post("/notify")
        def http_notify():
            """
            If this is a better predecessor, adopt it.
            """
            data = request.get_json()
            cand = NodeInfo(data["hostname"], data["port"], int(data["id"]))
            # Register new predecessor if I don't have one or the candidate is in betwen me and my current predecessor
            if node.predecessor is None or node.isWithinInterval(cand.nodeID, node.predecessor.nodeID, node.nodeInfo.nodeID):
                node.predecessor = cand

            # Case 1: two-node bootstrap (my successor is me)
            if node.successor is None or node.successor.nodeID == node.nodeInfo.nodeID:
                node.successor = cand
                node.finger[0] = node.successor
            # Case 2: general improvement (cand in (self, successor))
            elif node.isWithinInterval(cand.nodeID, node.nodeInfo.nodeID, node.successor.nodeID):
                node.successor = cand
                node.finger[0] = node.successor

            return jsonify({"ok": True})
        
        @app.post("/update")
        def http_update():
            # Check successor's predecessor
            try:
                resp = node.rpcGet(node.successor, "/get_predecessor")
                x = resp.get("predecessor")
            except Exception:
                x = None
            # Replace my successor info with with successors predecessor if:
            # My successor is myself or
            # Succesors predecessor between me and my successor
            if x:
                xinfo = NodeInfo(str(x["hostname"]), int(x["port"]), int(x["nodeID"]))
                if node.successor.nodeID == node.nodeInfo.nodeID or node.isWithinInterval(xinfo.nodeID, node.nodeInfo.nodeID, node.successor.nodeID):
                    node.successor = xinfo
                    node.finger[0] = node.successor

            # Notify the (new) successor know about us
            try:
                node.rpcPost(node.successor, "/notify", {"hostname": node.nodeInfo.hostname, "port": node.nodeInfo.port, "id": node.nodeInfo.nodeID})
            except Exception:
                pass
            #node.buildFingerTable()
            return jsonify({"ok": True, "successor": asdict(node.successor)})
        
        @app.post("/repair_hand")
        def http_repair_hand():
            node.buildFingerTable()
            return jsonify({"ok": True, "fingers": [asdict(f) for f in node.finger]})
        
        @app.get("/storage/<key>")
        def http_get_content(key):
            value = node.getValue(key)
            if value is not None:
                return value, 200, {'Content-Type': 'text/plain'}
            else:
                return "Not found", 404, {'Content-Type': 'text/plain'}

        @app.put("/storage/<key>")
        def http_put_content(key):
            value = request.data.decode("utf-8")
            success = node.storeValue(key, value)
            if success:
                return "Success", 200, {'Content-Type': 'text/plain'}
            else:
                return "Error", 500, {'Content-Type': 'text/plain'}
            
        @app.get("/network")
        def http_network():
            return jsonify(node.get_all_hosts_json()), 200
        
        @app.before_request
        def start_timer():
            g._t0 = time.perf_counter()

        @app.after_request
        def _stop_timer(resp):
            if hasattr(g, "_t0"):
                dt_ms = (time.perf_counter() - g._t0) * 1000

                resp.headers["Server-Timing"] = f"app;dur={dt_ms:.2f}"

                resp.headers["X-Response-Time"] = f"{dt_ms:.2f} ms"

                resp.headers["Timing-Allow-Origin"] = "*"
                resp.headers["Access-Control-Expose-Headers"] = "Server-Timing, X-Response-Time"
                print(f"Request Time: {dt_ms:.2f}")
            return resp

        app.run(host="0.0.0.0", port=self.nodeInfo.port, debug=False)

if __name__ == '__main__':
    if len(sys.argv) > 3:
        
        # Predefine in case of nonsense
        contactNode: NodeInfo
        port: int = 30324
        m: int = 2
        ringSize: int = 2 ** m
        ttl: int = 30
        mode: str = "create"

        # Get launch arguments
        port = int(sys.argv[1])
        m = int(sys.argv[2])
        ringSize= 2 ** m
        ttl = int(sys.argv[3])
        mode = str(sys.argv[4])
        
        # Start countdown early in case of errors
        threading.Thread(target=shutdown_after, args=(ttl,), daemon=True).start()

        # Grab hostname
        hostname: str = socket.gethostname()
        hostname = hostname.split('.')[0] # grab subdomain
        print(str(hostname) + ":" + str(socket))
        
        # Init node
        node = Node(hostname, port, m, ringSize)

        # Select mode
        if (mode == "join"):
            print("Joining existing ring")
            contactHostname = sys.argv[5]
            if not (contactHostname):
                raise ValueError("Need a connecting node hostname")
            contactPort = int(sys.argv[6])
            if not (contactPort):
                raise ValueError("Need a connecting node port number")
            completeHostname: str = str(contactHostname) + str(contactPort)
            contactNode = NodeInfo(contactHostname, contactPort, getShaHash(completeHostname, ringSize))
            print("contact node: " + str(contactNode.hostname) + " " + str(contactNode.port) + " " + str(contactNode.nodeID)) 
            node.joinRing(contactNode)
            #initialNodes = json.loads(contactNode)
            #if not isinstance(initialNodes, list):
            #    raise TypeError("Could not create list from JSON string")
        elif (mode == "create"):
            print("Creating new ring")
            node.createRing()
        else:
            raise TypeError("Mode needs to be defined")
        
        #Start webservice
        node.setupRoutes()

    else:
        print("Error: Missing arguments. Usage: python3 server.py [PORT] [BITS] [TTL] [MODE(create/join)], [NODE(first contact point)] ")

    
    
    

    
    
    
