import threading
import time
import requests
import json, yaml
from urllib.parse import parse_qs

class DataFetcher:
    def __init__(self):
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self.fetch_proc, daemon=True)
        self.prices = []

    def start(self):
        if not self._thread.is_alive():
            self._thread.start()

    def stop(self):
        self._stop_event.set()

    def fetch_proc(self):
        while not self._stop_event.is_set():
            try:
                response = requests.get("http://10.0.0.47/getData")
                content_type = response.headers["Content-Type"]

                if response.status_code != 201:
                    raise requests.exceptions.RequestException(response.status_code)

                if content_type.startswith("application/json"):
                    data = json.loads(response.text)
                elif content_type.startswith("application/x-www-form-urlencoded"):
                    data = parse_qs(response.text)
                elif content_type.startswith("application/yaml"):
                    data = yaml.load(response.text, Loader=yaml.UnsafeLoader)

                self.prices = data

            except Exception as e:
                print(f"Error fetching price: {e}")

            time.sleep(10)

    def get_prices(self):
        return self.prices
