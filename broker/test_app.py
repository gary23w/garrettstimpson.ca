import asyncio
import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException

import app as broker


class FakeRequest:
    def __init__(self, payload, authorization=""):
        self._raw = json.dumps(payload).encode()
        self.headers = {
            "authorization": authorization,
            "content-length": str(len(self._raw)),
        }

    async def stream(self):
        yield self._raw


class FakeConnection:
    def close(self):
        pass


class RedirectResponse:
    status = 302

    def getheader(self, name):
        return "https://other.example/sample.bin" if name.lower() == "location" else None


class BrokerSecurityTests(unittest.TestCase):
    def test_onion_authority_must_match_exactly(self):
        valid = "a" * 56 + ".onion"
        self.assertEqual(broker.normalize_onion_url(valid), f"http://{valid}/")
        for value in (
            f"http://{valid}.example.com/",
            f"http://user@{valid}/",
            f"http://{valid}:8080/",
            "http://example.com/path/aaaaaaaaaaaaaaaa.onion",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                broker.normalize_onion_url(value)

    def test_dns_resolution_rejects_any_non_public_address(self):
        answers = [
            (None, None, None, None, ("93.184.216.34", 443)),
            (None, None, None, None, ("127.0.0.1", 443)),
        ]
        with patch.object(broker.socket, "getaddrinfo", return_value=answers):
            with self.assertRaisesRegex(ValueError, "non-public"):
                broker.public_addresses("example.test", 443)

    def test_plain_http_samples_are_disabled_by_default(self):
        with patch.dict(broker.os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "must use https"):
                broker.pinned_public_get("http://example.com/sample.bin")

    def test_sample_redirect_cannot_escape_authorized_host(self):
        with patch.object(broker, "pinned_public_get", return_value=(FakeConnection(), RedirectResponse())):
            with self.assertRaisesRegex(ValueError, "outside the authorized target"):
                broker.fetch_sample("https://safe.example/sample.bin")

    def test_validated_address_is_pinned_for_the_socket(self):
        class Connection(FakeConnection):
            def request(self, *_args, **_kwargs):
                self._create_connection(("ignored", 443), timeout=7, source_address=None)

            def getresponse(self):
                return object()

        connection = Connection()
        with patch.object(broker, "public_addresses", return_value=["93.184.216.34"]), \
             patch.object(broker.http.client, "HTTPSConnection", return_value=connection), \
             patch.object(broker.socket, "create_connection", return_value=object()) as connect:
            returned, _ = broker.pinned_public_get("https://example.com/sample.bin")
        self.assertIs(returned, connection)
        connect.assert_called_once_with(("93.184.216.34", 443), 7, None)

    def test_worker_reverse_tool_name_has_a_broker_alias(self):
        self.assertIn("sample URL is required", broker.TOOLS["reverse_analyze"]({}))

    def test_run_fails_closed_without_a_strong_token(self):
        request = FakeRequest({"tool": "onion_search", "args": {"query": "x"}})
        with patch.object(broker, "BROKER_TOKEN", ""):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(broker.run(request))
        self.assertEqual(raised.exception.status_code, 503)

    def test_run_rejects_wrong_bearer(self):
        request = FakeRequest({"tool": "onion_search", "args": {"query": "x"}}, "Bearer wrong")
        with patch.object(broker, "BROKER_TOKEN", "x" * 32):
            with self.assertRaises(HTTPException) as raised:
                asyncio.run(broker.run(request))
        self.assertEqual(raised.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
