from urllib.parse import urlparse
from scanners.base import BaseScanner, Finding


class HeaderScanner(BaseScanner):
    name = "HeaderScanner"

    REQUIRED_HEADERS = {
        "Content-Security-Policy": (
            "Medium",
            "Define a strong Content-Security-Policy to restrict script and resource origins.",
        ),
        "X-Frame-Options": (
            "Low",
            "Set X-Frame-Options to DENY or SAMEORIGIN to reduce clickjacking risk.",
        ),
        "X-Content-Type-Options": (
            "Low",
            "Set X-Content-Type-Options to nosniff to prevent MIME-type confusion.",
        ),
    }

    def scan(self, crawl_data):
        findings = []
        for url in crawl_data.get("visited_urls", []):
            response = self.requester.get(url)
            if not response:
                continue

            headers = {k.lower(): v for k, v in response.headers.items()}

            for header, (severity, remediation) in self.REQUIRED_HEADERS.items():
                if header.lower() not in headers:
                    findings.append(
                        Finding(
                            scanner=self.name,
                            vulnerability=f"Missing {header} Header",
                            url=url,
                            severity=severity,
                            evidence=f"Response header '{header}' was not present.",
                            remediation=remediation,
                        )
                    )

            if urlparse(url).scheme == "https" and "strict-transport-security" not in headers:
                findings.append(
                    Finding(
                        scanner=self.name,
                        vulnerability="Missing Strict-Transport-Security Header",
                        url=url,
                        severity="Medium",
                        evidence="HTTPS endpoint did not send Strict-Transport-Security (HSTS).",
                        remediation="Enable HSTS (e.g., Strict-Transport-Security: max-age=31536000; includeSubDomains).",
                    )
                )

        return findings
