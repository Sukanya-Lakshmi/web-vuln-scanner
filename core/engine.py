from urllib.parse import urlparse
from core.crawler import WebCrawler
from core.requester import Requester
from scanners.headers import HeaderScanner
from scanners.xss import XSSScanner


class ScanEngine:
    def __init__(self, db, timeout=8, delay=0.15):
        self.db = db
        self.timeout = timeout
        self.delay = delay

    @staticmethod
    def _is_valid_target(url):
        parsed = urlparse(url.strip())
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    def run_scan(self, target_url, max_depth=2):
        target_url = target_url.strip()
        if not self._is_valid_target(target_url):
            raise ValueError("Target URL must start with http:// or https:// and include a host.")

        scan_id = self.db.create_scan(target_url=target_url, max_depth=max_depth)
        try:
            requester = Requester(timeout=self.timeout, delay=self.delay)
            crawler = WebCrawler(requester, max_depth=max_depth)
            crawl_data = crawler.crawl(target_url)

            visited_count = len(crawl_data.get("visited_urls", []))
            self.db.update_scan_stats(scan_id, visited_count)

            scanners = [
                HeaderScanner(requester),
                XSSScanner(requester),
            ]

            all_findings = []
            for scanner in scanners:
                results = scanner.scan(crawl_data)
                all_findings.extend(f.to_dict() for f in results)

            self.db.save_findings(scan_id, all_findings)
            self.db.update_scan_status(scan_id, "completed")
            return scan_id
        except Exception:
            self.db.update_scan_status(scan_id, "failed")
            raise
