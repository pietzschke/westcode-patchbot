import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from inventory.github_app import GitHubApp, RestGitHubClient


class Resp:
    def __init__(self, payload=None, status_code=200, links=None):
        self.payload = payload
        self.status_code = status_code
        self.links = links or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def request(self, method, url, headers=None, json=None, params=None, timeout=None):
        self.calls.append((method, url, headers, json, params))
        handler = self.routes.get((method, url))
        if callable(handler):
            return handler(json=json, params=params)
        return handler or Resp({}, 404)

    def post(self, url, headers=None, timeout=None):
        return self.request("POST", url, headers=headers, timeout=timeout)


def _app(session):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return key, GitHubApp(app_id="12345", installation_id="678", private_key_pem=pem, session=session)


def test_installation_token_is_minted_with_short_lived_app_jwt_and_cached():
    url = "https://api.github.com/app/installations/678/access_tokens"
    session = FakeSession({("POST", url): Resp({"token": "ghs_test", "expires_at": "2099-01-01T00:00:00Z"}, 201)})
    key, app = _app(session)

    assert app.installation_token() == "ghs_test"
    assert app.installation_token() == "ghs_test"
    assert len(session.calls) == 1

    headers = session.calls[0][2]
    claims = jwt.decode(headers["Authorization"].removeprefix("Bearer "), key.public_key(), algorithms=["RS256"])
    assert claims["iss"] == "12345"
    assert claims["exp"] - int(time.time()) <= 600


class StaticToken:
    def installation_token(self):
        return "ghs_test"


def test_push_branch_refuses_non_patchbot_branches(tmp_path):
    client = RestGitHubClient(app=StaticToken(), session=FakeSession(), runner=lambda *a, **kw: (0, "", ""))
    for branch in ("main", "renovate/lodash-4.x", "patchbotx/evil", ""):
        with pytest.raises(ValueError):
            client.push_branch("westcoder/mdb", branch, tmp_path)


def test_push_branch_passes_token_via_env_not_argv(tmp_path):
    seen = {}

    def runner(argv, cwd=None, env=None):
        seen["argv"], seen["env"] = argv, env
        return (0, "", "")

    client = RestGitHubClient(app=StaticToken(), session=FakeSession(), runner=runner)
    client.push_branch("westcoder/mdb", "patchbot/lodash-4.17.21", Path(tmp_path))

    assert "ghs_test" not in " ".join(seen["argv"])
    assert "--force" not in seen["argv"]
    assert seen["argv"][-1] == "HEAD:refs/heads/patchbot/lodash-4.17.21"
    assert any("AUTHORIZATION" in v for v in seen["env"].values())


def test_upsert_marker_comment_updates_existing_comment():
    base = "https://api.github.com/repos/westcoder/mdb"
    session = FakeSession({
        ("GET", f"{base}/issues/41/comments"): Resp([
            {"id": 1, "body": "unrelated"},
            {"id": 2, "body": "<!-- patchbot:triage -->\nold analysis"},
        ]),
        ("PATCH", f"{base}/issues/comments/2"): Resp({"id": 2}),
    })
    client = RestGitHubClient(app=StaticToken(), session=session)

    assert client.upsert_marker_comment("westcoder/mdb", 41, "<!-- patchbot:triage -->", "new analysis") == 2
    method, url, headers, body, _ = session.calls[-1]
    assert (method, url) == ("PATCH", f"{base}/issues/comments/2")
    assert body["body"].startswith("<!-- patchbot:triage -->")
    assert headers["Authorization"] == "Bearer ghs_test"


def test_upsert_marker_comment_creates_when_missing():
    base = "https://api.github.com/repos/westcoder/mdb"
    session = FakeSession({
        ("GET", f"{base}/issues/41/comments"): Resp([]),
        ("POST", f"{base}/issues/41/comments"): Resp({"id": 9}, 201),
    })
    client = RestGitHubClient(app=StaticToken(), session=session)
    assert client.upsert_marker_comment("westcoder/mdb", 41, "<!-- m -->", "body") == 9
