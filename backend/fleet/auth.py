import hashlib
import hmac
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from fleet.models import Host


class HostTokenAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request: Request) -> tuple[None, Host]:
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword.lower().encode("ascii"):
            raise AuthenticationFailed("Missing or invalid Authorization Bearer header.")

        if len(auth) != 2:
            raise AuthenticationFailed("Invalid Authorization Bearer header format.")

        try:
            raw_token = auth[1].decode("utf-8")
        except UnicodeError as exc:
            raise AuthenticationFailed("Invalid token encoding.") from exc

        if not raw_token:
            raise AuthenticationFailed("Empty agent token.")

        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        host = (
            Host.objects.filter(agent_token_hash=token_hash)
            .exclude(agent_token_hash="")
            .first()
        )
        if host is None or not hmac.compare_digest(host.agent_token_hash, token_hash):
            raise AuthenticationFailed("Invalid agent token.")

        return (None, host)

    def authenticate_header(self, request: Request) -> str:
        return self.keyword
