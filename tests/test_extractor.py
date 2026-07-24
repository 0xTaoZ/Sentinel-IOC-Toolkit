import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR_PATH = ROOT / "python-backend" / "extractor.py"


def load_extractor():
    spec = importlib.util.spec_from_file_location("extractor", EXTRACTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SentinelEngineTests(unittest.TestCase):
    def scan_text(self, text):
        extractor = load_extractor()
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write(text)
            path = handle.name

        return extractor.SentinelEngine(path).start_scan()

    def test_scans_iocs_without_optional_api_dependencies(self):
        log_text = "\n".join(
            [
                "failed login from 192.168.1.10",
                "callback http://example.test/dropper.exe",
                "md5 44d88612fea8a8f36de82e1278abbb03",
                "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ]
        )

        report = self.scan_text(log_text)

        self.assertEqual(["192.168.1.10"], [item["value"] for item in report["findings"]["ipv4"]])
        self.assertEqual(["http://example.test/dropper.exe"], report["findings"]["url"])
        self.assertEqual(["44d88612fea8a8f36de82e1278abbb03"], report["findings"]["md5"])
        self.assertEqual(
            ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
            report["findings"]["sha256"],
        )

    def test_ignores_invalid_ipv4_octets(self):
        report = self.scan_text("not an IP: 999.999.999.999\nreal IP: 10.0.0.5")

        self.assertEqual(["10.0.0.5"], [item["value"] for item in report["findings"]["ipv4"]])

    def test_returns_ipv6_matches_as_strings(self):
        report = self.scan_text("tunnel from 2001:0db8:85a3:0000:0000:8a2e:0370:7334")

        self.assertEqual(["2001:0db8:85a3:0000:0000:8a2e:0370:7334"], report["findings"]["ipv6"])

    def test_extracts_bare_domains_without_duplicating_url_hosts(self):
        report = self.scan_text(
            "\n".join(
                [
                    "dns query for staging-c2.example.org",
                    "callback http://drop.example.test/payload",
                    "downloaded file update.sh",
                    "real IP: 10.0.0.5",
                ]
            )
        )

        self.assertEqual(["staging-c2.example.org"], report["findings"]["domain"])

    def test_normalizes_defanged_urls_and_domains(self):
        report = self.scan_text(
            "\n".join(
                [
                    "phishing callback hxxp://malware[.]example[.]test/payload",
                    "dns beacon for c2[.]example[.]org",
                ]
            )
        )

        self.assertEqual(["http://malware.example.test/payload"], report["findings"]["url"])
        self.assertEqual(["c2.example.org"], report["findings"]["domain"])


if __name__ == "__main__":
    unittest.main()
