import base64
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("publisher", Path(__file__).parents[1] / "publish_testflight_release.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)


def document(version="1.0", build="10", app_id="123", internal_state="IN_BETA_TESTING", external_state="IN_BETA_TESTING"):
    return {
        "data": {"id": build, "type": "builds", "attributes": {
            "version": build, "processingState": "VALID", "expired": False,
            "expirationDate": publisher.iso(NOW + timedelta(days=80)), "minOsVersion": "17.0"},
            "relationships": {"app": {"data": {"type": "apps", "id": app_id}},
                              "preReleaseVersion": {"data": {"type": "preReleaseVersions", "id": "v"}},
                              "buildBetaDetail": {"data": {"type": "buildBetaDetails", "id": "b"}}}},
        "included": [{"type": "preReleaseVersions", "id": "v", "attributes": {"version": version, "platform": "IOS"}},
                     {"type": "buildBetaDetails", "id": "b", "attributes": {"internalBuildState": internal_state, "externalBuildState": external_state}}]}


class FakeApple:
    def __init__(self, documents, bundle="example.couple", internal=True):
        self.documents = documents
        self.bundle = bundle
        self.internal = internal

    def get(self, path, params=None):
        if path == "/v1/apps/123":
            return {"data": {"attributes": {"bundleId": self.bundle}}}
        return self.documents[path.rsplit("/", 1)[1]]

    def list_all(self, path):
        if "betaGroups?" in path:
            return [{"id": "group-1", "attributes": {"name": "Testers", "isInternalGroup": self.internal}}]
        return [{"id": key} for key in self.documents]


class PublisherTests(unittest.TestCase):
    def test_selects_numeric_latest_version_and_build_for_the_group(self):
        client = FakeApple({"a": document(build="9"), "b": document(build="10")})
        feed = publisher.generate_feed(client, "123", "Testers", "example.couple", NOW)
        self.assertEqual(feed["release"]["build"], "10")
        client.documents["c"] = document(version="1.1", build="1")
        self.assertEqual(publisher.generate_feed(client, "123", "group-1", "example.couple", NOW)["release"]["version"], "1.1")

    def test_processing_unreleased_expired_and_wrong_platform_are_not_announced(self):
        for modification in ["processing", "expired", "past_expiry", "not_testing", "other_platform"]:
            with self.subTest(modification=modification):
                value = document()
                if modification == "processing": value["data"]["attributes"]["processingState"] = "PROCESSING"
                if modification == "expired": value["data"]["attributes"]["expired"] = True
                if modification == "past_expiry": value["data"]["attributes"]["expirationDate"] = publisher.iso(NOW)
                if modification == "not_testing": value["included"][1]["attributes"]["internalBuildState"] = "READY_FOR_BETA_TESTING"
                if modification == "other_platform": value["included"][0]["attributes"]["platform"] = "MAC_OS"
                feed = publisher.generate_feed(FakeApple({"a": value}), "123", "Testers", "example.couple", NOW)
                self.assertFalse(feed["enabled"]); self.assertIsNone(feed["release"])

    def test_external_group_uses_external_availability(self):
        value = document(external_state="WAITING_FOR_BETA_REVIEW")
        feed = publisher.generate_feed(FakeApple({"a": value}, internal=False), "123", "Testers", "example.couple", NOW)
        self.assertFalse(feed["enabled"])
        value = document(internal_state="READY_FOR_BETA_TESTING")
        feed = publisher.generate_feed(FakeApple({"a": value}, internal=False), "123", "Testers", "example.couple", NOW)
        self.assertTrue(feed["enabled"])

    def test_different_app_or_group_is_a_configuration_error(self):
        with self.assertRaises(ValueError):
            publisher.generate_feed(FakeApple({}, bundle="example.timebank"), "123", "Testers", "example.couple", NOW)
        with self.assertRaises(ValueError):
            publisher.generate_feed(FakeApple({}), "123", "Unknown", "example.couple", NOW)
        with self.assertRaises(ValueError):
            publisher.generate_feed(FakeApple({"a": document(app_id="456")}), "123", "Testers", "example.couple", NOW)

    def test_next_page_is_followed_and_credentials_never_go_to_another_host(self):
        client = publisher.AppleClient("not-a-real-token")
        with patch.object(client, "get", side_effect=[{"data": [1], "links": {"next": publisher.API + "/next"}}, {"data": [2]}]):
            self.assertEqual(client.list_all("/first"), [1, 2])
        with self.assertRaises(ValueError): client.get("https://example.com/stolen")

    def test_emergency_unlock_needs_no_apple_key(self):
        with tempfile.TemporaryDirectory() as output, patch.dict(os.environ, {"APP_BUNDLE_ID": "example.couple", "REQUIRE_LATEST_BUILD": "false"}, clear=True), patch("sys.argv", ["publisher", output]):
            publisher.main()
            feed = json.loads((Path(output) / "release.json").read_text())
            self.assertFalse(feed["enabled"]); self.assertIsNone(feed["release"])

    def test_es256_token_verifies_with_openssl(self):
        private = subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout"], capture_output=True, check=True).stdout
        signed = publisher.token("key-id", "issuer-id", private.decode())
        header, payload, signature = signed.split(".")
        decode = lambda text: base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        self.assertEqual(json.loads(decode(header))["alg"], "ES256")
        claims = json.loads(decode(payload))
        self.assertEqual(claims["iss"], "issuer-id")
        self.assertEqual(claims["aud"], "appstoreconnect-v1")
        self.assertLess(claims["exp"] - claims["iat"], 1200)
        raw = decode(signature); self.assertEqual(len(raw), 64)
        integers = []
        for part in [raw[:32], raw[32:]]:
            part = part.lstrip(b"\0") or b"\0"
            if part[0] & 0x80: part = b"\0" + part
            integers.append(b"\x02" + bytes([len(part)]) + part)
        body = b"".join(integers)
        der = b"\x30" + bytes([len(body)]) + body
        with tempfile.TemporaryDirectory() as folder:
            public = subprocess.run(["openssl", "pkey", "-pubout"], input=private, capture_output=True, check=True).stdout
            (Path(folder) / "key.pem").write_bytes(public); (Path(folder) / "signature").write_bytes(der)
            result = subprocess.run(["openssl", "dgst", "-sha256", "-verify", folder + "/key.pem", "-signature", folder + "/signature"], input=(header + "." + payload).encode(), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_invalid_numeric_components_and_signature_are_rejected(self):
        for value in ["", "1..0", "1.2.3.4", "-1", "１", "9999999999"]:
            with self.assertRaises(ValueError): publisher.number(value)
        self.assertLess(publisher.number("2.9"), publisher.number("2.10"))
        for value in [b"", b"bogus", b"\x30\x03\x02\x01\x01"]:
            with self.assertRaises(ValueError): publisher.jose_signature(value)


if __name__ == "__main__":
    unittest.main()
