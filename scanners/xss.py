from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from scanners.base import BaseScanner, Finding


class XSSScanner(BaseScanner):
    name = "XSSScanner"
    MARKER = "SCANNER_REFLECT_PROBE"

    def __init__(self, requester):
        super().__init__(requester)
        self.reported = set()

    def _record_if_reflected(self, target_url, param_name, response):
        key = (target_url, param_name)
        if not response or key in self.reported:
            return None
        if self.MARKER in response.text:
            self.reported.add(key)
            return Finding(
                scanner=self.name,
                vulnerability="Potential Reflected XSS (Unencoded Input Reflection)",
                url=target_url,
                severity="High",
                evidence=f"Marker '{self.MARKER}' reflected in response for parameter '{param_name}'.",
                remediation=(
                    "Apply context-aware output encoding before rendering user input "
                    "and enforce a strict Content-Security-Policy."
                ),
            )
        return None

    def scan(self, crawl_data):
        findings = []

        for url in crawl_data.get("param_urls", []):
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            for param in params:
                mutated = {k: v[0] if v else "" for k, v in params.items()}
                mutated[param] = self.MARKER
                test_url = urlunparse(parsed._replace(query=urlencode(mutated)))
                finding = self._record_if_reflected(url, param, self.requester.get(test_url))
                if finding:
                    findings.append(finding)

        for form in crawl_data.get("forms", []):
            action_url = form.get("action_url")
            method = form.get("method", "get")
            inputs = form.get("inputs", [])
            if not action_url or not inputs:
                continue

            base_data = {item["name"]: item.get("value", "test") for item in inputs}
            for item in inputs:
                field_name = item["name"]
                payload_data = dict(base_data)
                payload_data[field_name] = self.MARKER
                resp = (
                    self.requester.post(action_url, data=payload_data)
                    if method == "post"
                    else self.requester.get(action_url, params=payload_data)
                )
                finding = self._record_if_reflected(action_url, field_name, resp)
                if finding:
                    findings.append(finding)

        return findings
