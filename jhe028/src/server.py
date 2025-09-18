from flask import Flask
import threading
import time
import sys
import os
import socket
import hashlib
import requests
import logging

logging.basicConfig(level=logging.INFO)




app = Flask(__name__)
port = 8080 #36754
hostname = "ingenting" #c9-1

@app.route('/helloworld')
def helloworld():
    return str(hostname) + ":" + str(port)

def shutdown_after(delay):
    time.sleep(delay)
    print("Shutting down")
    os._exit(0)

if __name__ == '__main__': 
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    hostname = socket.gethostname()
    hostname = hostname.split('.')[0]
    print(str(hostname) + ":" + str(socket))
    threading.Thread(target=shutdown_after, args=(30,), daemon=True).start()
    app.run(host="0.0.0.0", port=port, debug=False)
