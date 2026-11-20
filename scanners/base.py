from abc import ABC, abstractmethod


class Finding:
    def __init__(self, scanner, vulnerability, url, severity, evidence, remediation):
        self.scanner = scanner
        self.vulnerability = vulnerability
        self.url = url
        self.severity = severity  # High, Medium, Low, Info
        self.evidence = evidence
        self.remediation = remediation

    def to_dict(self):
        return {
            "scanner": self.scanner,
            "vulnerability": self.vulnerability,
            "url": self.url,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


class BaseScanner(ABC):
    name = "BaseScanner"

    def __init__(self, requester):
        self.requester = requester

    @abstractmethod
    def scan(self, crawl_data):
        """Analyze crawled targets and return a list of Finding objects."""
        raise NotImplementedError
