from core.requester import Requester
from core.crawler import WebCrawler
from scanners.headers import HeaderScanner

req = Requester(timeout=8, delay=0.1)
crawler = WebCrawler(req, max_depth=2)
crawl_data = crawler.crawl("http://127.0.0.1:5001")

header_scanner = HeaderScanner(req)
findings = header_scanner.scan(crawl_data)

print(f"Total header findings: {len(findings)}")
for item in findings[:8]:
    print(f"  [{item.severity}] {item.vulnerability} -> {item.url}")
