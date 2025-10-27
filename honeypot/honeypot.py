import socketserver
import json
import threading
import datetime
import os

LOGFILE = "honeypot_logs.jsonl"
BANNER = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n"

def log_event(event):
    with open(LOGFILE, "a") as f:
        f.write(json.dumps(event) + "\n")

class HoneypotHandler(socketserver.StreamRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        ts = datetime.datetime.utcnow().isoformat()
        self.request.sendall(BANNER.encode())
        event = {"ts": ts, "ip": ip, "port": self.client_address[1], "action": "connect"}
        log_event(event)

        try:
            self.request.sendall(b"login: ")
            while True:
                data = self.rfile.readline()
                if not data:
                    break
                cmd = data.decode(errors="ignore").rstrip("\r\n")
                ev = {"ts": datetime.datetime.utcnow().isoformat(), "ip": ip, "cmd": cmd}
                log_event(ev)
                self.request.sendall(b"bash: " + cmd.encode() + b": command not found\r\n")
        except Exception as e:
            err = {"ts": datetime.datetime.utcnow().isoformat(), "ip": ip, "error": str(e)}
            log_event(err)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 2222  # run on non-standard port for safety; map port 22 in a VM if desired
    print(f"Starting honeypot on {HOST}:{PORT}")
    server = ThreadedTCPServer((HOST, PORT), HoneypotHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down")
        server.shutdown()
        server.server_close()
