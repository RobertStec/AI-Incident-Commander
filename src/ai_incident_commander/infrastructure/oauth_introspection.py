"""Fail-closed RFC 7662 token verifier for the Observability MCP resource server.

The composition root owns the HTTP client (TLS, timeouts, proxy policy, lifecycle).
An explicitly configured, HTTPS introspection endpoint is the only authority;
client-provided issuers, audiences and introspection URLs are never accepted.
"""

from datetime import UTC, datetime
from json import JSONDecodeError, loads
from typing import Any

import httpx
from mcp.server.auth.provider import AccessToken

MAX_INTROSPECTION_RESPONSE_BYTES = 16_384
MAX_BEARER_TOKEN_LENGTH = 8192


def _require_https_url(value: str, *, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be an HTTPS URL.")
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, ValueError):
        raise ValueError(f"{name} must be an HTTPS URL.") from None
    if (
        url.scheme != "https"
        or not url.host
        or bool(url.username)
        or bool(url.password)
        or url.query
        or url.fragment
        or str(url) != value
    ):
        raise ValueError(f"{name} must be an exact HTTPS URL without credentials or query.")
    return value


class OAuthIntrospectionVerifier:
    """MCP TokenVerifier backed by a real OAuth 2.0 introspection endpoint.

    No token cache: revocation takes effect on the next request. Any failure to
    validate the introspection response denies the token, without exposing it.
    This verifier never signs tokens, authenticates users, or creates grants.
    """

    def __init__(
        self,
        *,
        http_client: httpx.AsyncClient,
        introspection_url: str,
        issuer_url: str,
        resource_url: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        self._http = http_client
        self._endpoint = _require_https_url(introspection_url, name="Introspection endpoint")
        self._issuer = _require_https_url(issuer_url, name="OAuth issuer")
        self._resource = _require_https_url(resource_url, name="MCP resource")
        if not client_id or client_id != client_id.strip() or any(c.isspace() for c in client_id):
            raise ValueError("OAuth introspection client_id must be nonempty without whitespace.")
        if not client_secret:
            raise ValueError("OAuth introspection client_secret must be provided.")
        self._client_id = client_id
        self._auth = httpx.BasicAuth(client_id, client_secret)

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return a verified identity, or deny access on any untrusted response."""
        if (
            not isinstance(token, str)
            or not token
            or len(token) > MAX_BEARER_TOKEN_LENGTH
            or not token.isascii()
            or any(char.isspace() for char in token)
        ):
            return None
        body = bytearray()
        try:
            async with self._http.stream(
                "POST",
                self._endpoint,
                data={"token": token, "token_type_hint": "access_token"},
                auth=self._auth,
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    return None
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > MAX_INTROSPECTION_RESPONSE_BYTES:
                        return None
                    body.extend(chunk)
        except httpx.RequestError:
            return None

        try:
            payload: Any = loads(body)
        except (JSONDecodeError, UnicodeDecodeError):
            return None
        if not isinstance(payload, dict) or payload.get("active") is not True:
            return None

        # The issuer is pinned by the fixed introspection endpoint. If the
        # authorization server also supplies iss, require exact agreement.
        if "iss" in payload and payload["iss"] != self._issuer:
            return None
        if payload.get("token_type") not in (None, "Bearer"):
            return None

        audience = payload.get("aud")
        if not (
            audience == self._resource
            or (
                isinstance(audience, list)
                and all(isinstance(item, str) for item in audience)
                and self._resource in audience
            )
        ):
            return None

        client_id = payload.get("client_id")
        scope = payload.get("scope")
        subject = payload.get("sub")
        expires_at = payload.get("exp")
        not_before = payload.get("nbf")
        if (
            not isinstance(client_id, str)
            or not client_id
            or not client_id.strip()
            or not isinstance(scope, str)
            or not scope.strip()
            or (subject is not None and (not isinstance(subject, str) or not subject.strip()))
            or type(expires_at) is not int
            or (not_before is not None and type(not_before) is not int)
        ):
            return None
        now = int(datetime.now(UTC).timestamp())
        if expires_at <= now or (not_before is not None and not_before > now):
            return None

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=list(dict.fromkeys(scope.split())),
            subject=subject,
            expires_at=expires_at,
            resource=self._resource,
        )
