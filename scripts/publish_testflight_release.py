#!/usr/bin/env python3
"""Publish this project's installable TestFlight release. Python + OpenSSL only."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

API = "https://api.appstoreconnect.apple.com"


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def number(value):
    parts = value.split(".")
    if not 1 <= len(parts) <= 3 or any(not p.isascii() or not p.isdigit() or len(p) > 9 for p in parts):
        raise ValueError("Version and build numbers must have one to three numeric components")
    return tuple(int(p) for p in parts) + (0,) * (3 - len(parts))


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def jose_signature(der):
    # OpenSSL performs ECDSA; JWT uses the same r/s values in fixed-width form.
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("Invalid ECDSA signature")
    offset, parts = 2, []
    for _ in range(2):
        if offset + 2 > len(der) or der[offset] != 0x02:
            raise ValueError("Invalid ECDSA integer")
        size = der[offset + 1]
        raw = der[offset + 2:offset + 2 + size]
        if len(raw) != size or not raw or raw[0] & 0x80:
            raise ValueError("Invalid ECDSA integer")
        raw = raw.lstrip(b"\0")
        if len(raw) > 32:
            raise ValueError("Invalid ES256 signature size")
        parts.append(raw.rjust(32, b"\0"))
        offset += size + 2
    if offset != len(der):
        raise ValueError("Unexpected signature data")
    return b"".join(parts)


def token(key_id, issuer_id, private_key):
    header = b64(json.dumps({"alg": "ES256", "kid": key_id, "typ": "JWT"}).encode())
    now = int(time.time())
    payload = b64(json.dumps({"iss": issuer_id, "iat": now - 30, "exp": now + 600, "aud": "appstoreconnect-v1"}).encode())
    unsigned = header + b"." + payload
    # The temporary key has owner-only permissions and is removed before returning.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".p8") as key:
        key.write(private_key); key.flush()
        result = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key.name], input=unsigned,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode:
            raise ValueError("Could not sign the API token; check ASC_PRIVATE_KEY is the original .p8 PEM")
    return (unsigned + b"." + b64(jose_signature(result.stdout))).decode()


class AppleClient:
    def __init__(self, bearer):
        self.bearer = bearer

    def get(self, path, params=None):
        url = path if path.startswith("https://") else API + path
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "api.appstoreconnect.apple.com":
            raise ValueError("Refusing to send Apple credentials to another host")
        if params:
            url += "?" + urlencode(params)
        request = Request(url, headers={"Authorization": "Bearer " + self.bearer, "Accept": "application/json"})
        with urlopen(request, timeout=30) as response:
            return json.load(response)

    def list_all(self, path):
        items = []
        while path:
            document = self.get(path)
            items.extend(document["data"])
            path = document.get("links", {}).get("next")
        return items


def candidate(document, app_id, internal, now):
    build = document["data"]
    attributes = build["attributes"]
    relations = build["relationships"]
    if relations.get("app", {}).get("data", {}).get("id") != app_id:
        raise ValueError("A tester-group build belongs to a different app")
    included = {(item["type"], item["id"]): item["attributes"] for item in document.get("included", [])}

    def related(name):
        relation = relations.get(name, {}).get("data")
        return included.get((relation["type"], relation["id"]), {}) if relation else {}

    prerelease = related("preReleaseVersion")
    beta = related("buildBetaDetail")
    state = beta.get("internalBuildState" if internal else "externalBuildState")
    if attributes.get("processingState") != "VALID" or attributes.get("expired") is not False or state != "IN_BETA_TESTING":
        return None
    if prerelease.get("platform") != "IOS":
        return None
    expires = timestamp(attributes["expirationDate"])
    if expires <= now:
        return None
    version, build_number, minimum_os = prerelease["version"], attributes["version"], attributes["minOsVersion"]
    number(version); number(build_number); number(minimum_os)
    return {"version": version, "build": build_number, "minimumOSVersion": minimum_os,
            "appStoreID": app_id, "expiresAt": iso(expires)}


def generate_feed(client, app_id, group_name, bundle_identifier, now):
    if not app_id.isascii() or not app_id.isdigit() or len(app_id) > 20:
        raise ValueError("ASC_APP_ID must be the numeric App Store Connect app ID")
    app = client.get("/v1/apps/" + app_id)["data"]
    if app["attributes"]["bundleId"] != bundle_identifier:
        raise ValueError("APP_BUNDLE_ID does not match ASC_APP_ID; refusing to publish another app's build")
    groups = client.list_all("/v1/apps/" + app_id + "/betaGroups?limit=200")
    matches = [g for g in groups if g["id"] == group_name or g["attributes"]["name"] == group_name]
    if len(matches) != 1:
        raise ValueError("ASC_BETA_GROUP must identify exactly one tester group for this app (name or ID)")
    group = matches[0]
    internal = group["attributes"]["isInternalGroup"]
    releases = []
    for build in client.list_all("/v1/betaGroups/" + group["id"] + "/builds?limit=200"):
        attributes = build.get("attributes", {})
        if attributes.get("expired") is True or attributes.get("processingState") not in (None, "VALID"):
            continue
        document = client.get("/v1/builds/" + build["id"], {"include": "app,preReleaseVersion,buildBetaDetail"})
        release = candidate(document, app_id, internal, now)
        if release:
            releases.append(release)
    latest = max(releases, key=lambda r: (number(r["version"]), number(r["build"])), default=None)
    return {"schemaVersion": 1, "bundleIdentifier": bundle_identifier, "checkedAt": iso(now),
            "enabled": latest is not None, "release": latest}


def required_env(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError("Missing repository configuration: " + name)
    return value


def main():
    bundle_identifier = required_env("APP_BUNDLE_ID")
    enabled = os.environ.get("REQUIRE_LATEST_BUILD", "true").lower()
    if enabled not in ("true", "false"):
        raise ValueError("REQUIRE_LATEST_BUILD must be true or false")
    now = datetime.now(timezone.utc)
    if enabled == "false":
        # An emergency unlock works even if Apple credentials have expired.
        feed = {"schemaVersion": 1, "bundleIdentifier": bundle_identifier, "checkedAt": iso(now), "enabled": False, "release": None}
    else:
        bearer = token(required_env("ASC_KEY_ID"), required_env("ASC_ISSUER_ID"), required_env("ASC_PRIVATE_KEY"))
        feed = generate_feed(AppleClient(bearer), required_env("ASC_APP_ID"), required_env("ASC_BETA_GROUP"), bundle_identifier, now)
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "_release_site")
    output.mkdir(parents=True, exist_ok=True)
    (output / "release.json").write_text(json.dumps(feed, indent=2) + "\n")
    (output / "index.html").write_text("<!doctype html><html lang='en'><meta charset='utf-8'><title>App release</title><p>TestFlight release metadata.</p></html>\n")
    print("Published release metadata for " + bundle_identifier + (" (update required)" if feed["enabled"] else " (gate disabled)"))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Never print request headers, the JWT, the PEM key, or Apple's response body.
        print("Release feed generation failed: " + str(error), file=sys.stderr)
        sys.exit(1)
