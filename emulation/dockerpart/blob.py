#!/usr/bin/env python3
import struct
import sys
from pathlib import Path

def create_blob(dockerfile_path, compose_path, out_path="payload.blob"):
    dockerfile_bytes = Path(dockerfile_path).read_bytes()
    compose_bytes = Path(compose_path).read_bytes()

    with open(out_path, "wb") as out:
        out.write(struct.pack(">I", len(dockerfile_bytes)))  # 4 bytes, big-endian
        out.write(struct.pack(">I", len(compose_bytes)))     # 4 bytes, big-endian
        out.write(dockerfile_bytes)
        out.write(compose_bytes)

    print(f"✅ Binary payload written to {out_path} ({len(dockerfile_bytes)+len(compose_bytes)+8} bytes)")

if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print("Usage: python make_blob.py Dockerfile docker-compose.yaml [payload.blob]")
        sys.exit(1)

    df = sys.argv[1]
    dc = sys.argv[2]
    output = sys.argv[3] if len(sys.argv) == 4 else "payload.blob"
    create_blob(df, dc, output)