from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup


class WebCrawler:
    def __init__(self, requester, max_depth=2):
        self.requester = requester
        self.max_depth = max_depth
        self.visited = set()
        self.forms = []
        self.param_urls = set()

    def _normalize_url(self, base_url, href):
        if not href:
            return None
        href = href.strip()
        if href.startswith(("http://", "https://")):
            full_url = href
        else:
            full_url = urljoin(base_url, href)

        parsed = urlparse(full_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return None
        # Guard against accidental "https://http://..." strings
        if "://" in parsed.netloc:
            return None

        cleaned = parsed._replace(fragment="").geturl()
        return cleaned

    def _extract_forms(self, page_url, soup):
        for form in soup.find_all("form"):
            action = form.get("action")
            target_url = urljoin(page_url, action) if action else page_url
            method = (form.get("method") or "get").strip().lower()

            inputs = []
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name:
                    continue
                input_type = (tag.get("type") or "text").strip().lower()
                value = tag.get("value") or "test"
                inputs.append({
                    "name": name,
                    "type": input_type,
                    "value": value,
                })

            self.forms.append({
                "page_url": page_url,
                "action_url": target_url,
                "method": method,
                "inputs": inputs,
            })

    def crawl(self, start_url):
        start_url = start_url.strip()
        queue = deque([(start_url, 0)])

        while queue:
            current_url, depth = queue.popleft()
            if current_url in self.visited or depth > self.max_depth:
                continue

            self.visited.add(current_url)
            response = self.requester.get(current_url)
            if not response or "text/html" not in response.headers.get("Content-Type", ""):
                continue

            # Track URLs that already carry query parameters (e.g., ?id=1)
            if parse_qs(urlparse(current_url).query):
                self.param_urls.add(current_url)

            soup = BeautifulSoup(response.text, "html.parser")
            self._extract_forms(current_url, soup)

            if depth < self.max_depth:
                for link in soup.find_all("a", href=True):
                    next_url = self._normalize_url(current_url, link["href"])
                    if (
                        next_url
                        and next_url not in self.visited
                        and self.requester.same_domain(start_url, next_url)
                    ):
                        queue.append((next_url, depth + 1))

        return {
            "visited_urls": sorted(self.visited),
            "param_urls": sorted(self.param_urls),
            "forms": self.forms,
        }
