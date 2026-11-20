import time
from urllib.parse import urlparse
import requests


class Requester:
    def __init__(self, timeout=8, delay=0.2, user_agent="SecScanner/1.0"):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def get(self, url, params=None, retries=2):
        for attempt in range(retries + 1):
            time.sleep(self.delay)
            try:
                return self.session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as exc:
                if attempt == retries:
                    print(f"[!] GET error for {url}: {exc}")
                    return None
                time.sleep(0.5 * (attempt + 1))

    def post(self, url, data=None):
        time.sleep(self.delay)
        try:
            return self.session.post(url, data=data, timeout=self.timeout)
        except requests.RequestException as exc:
            print(f"[!] POST error for {url}: {exc}")
            return None

    @staticmethod
    def same_domain(url_a, url_b):
        return urlparse(url_a).netloc == urlparse(url_b).netloc
