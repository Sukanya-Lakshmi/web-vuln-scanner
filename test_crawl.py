from core.requester import Requester
from core.crawler import WebCrawler

target = "http://127.0.0.1:5001"
req = Requester(timeout=8, delay=0.2)
crawler = WebCrawler(req, max_depth=2)
results = crawler.crawl(target)

print(f"Visited URLs ({len(results['visited_urls'])}):")
for u in results["visited_urls"][:10]:
    print(" -", u)

print(f"\nParameterized URLs ({len(results['param_urls'])}):")
for p in results["param_urls"][:10]:
    print(" -", p)

print(f"\nForms found ({len(results['forms'])}):")
for f in results["forms"]:
	field_names = [i["name"] for i in f["inputs"]]
	print(f" - [{f['method'].upper()}] {f['action_url']} -> fields: {field_names}")
