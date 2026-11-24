"""Opt-in integration tests against an explicitly configured Keycloak test realm."""

import asyncio
import os
import ssl
from pathlib import Path

import httpx
import pytest

from ai_incident_commander.infrastructure.oauth_introspection import (
    OAuthIntrospectionVerifier,
)

REQUIRED_SCOPE = "observability:logs:read"

REQUIRED_ENV = (
    "AIC_TEST_OAUTH_ISSUER_URL",
    "AIC_TEST_OAUTH_RESOURCE_URL",
    "AIC_TEST_OAUTH_CA_FILE",
    "AIC_TEST_OAUTH_WORKER_SECRET_FILE",
    "AIC_TEST_OAUTH_INTROSPECTION_SECRET_FILE",
)


def test_keycloak_issues_token_accepted_by_introspection_verifier() -> None:
    if os.environ.get("RUN_KEYCLOAK_OAUTH_TESTS") != "1":
        pytest.skip("Set RUN_KEYCLOAK_OAUTH_TESTS=1 to enable Keycloak integration tests")

    missing = [name for name in REQUIRED_ENV if not os.environ.get(name)]
    if missing:
        pytest.fail(f"Missing OAuth test settings: {', '.join(missing)}")

    issuer = os.environ["AIC_TEST_OAUTH_ISSUER_URL"]
    resource = os.environ["AIC_TEST_OAUTH_RESOURCE_URL"]

    worker_secret = (
        Path(os.environ["AIC_TEST_OAUTH_WORKER_SECRET_FILE"])
        .read_text(encoding="utf-8")
        .rstrip("\r\n")
    )

    introspection_secret = (
        Path(os.environ["AIC_TEST_OAUTH_INTROSPECTION_SECRET_FILE"])
        .read_text(encoding="utf-8")
        .rstrip("\r\n")
    )

    async def scenario() -> None:
        tls_context = ssl.create_default_context(cafile=os.environ["AIC_TEST_OAUTH_CA_FILE"])

        async with httpx.AsyncClient(
            verify=tls_context,
            timeout=10.0,
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = await client.post(
                f"{issuer}/protocol/openid-connect/token",
                auth=httpx.BasicAuth("incident-worker", worker_secret),
                data={
                    "grant_type": "client_credentials",
                    "scope": REQUIRED_SCOPE,
                },
            )

            assert response.status_code == 200

            token = response.json()["access_token"]
            assert isinstance(token, str) and token

            verifier = OAuthIntrospectionVerifier(
                http_client=client,
                introspection_url=(f"{issuer}/protocol/openid-connect/token/introspect"),
                issuer_url=issuer,
                resource_url=resource,
                client_id="observability-mcp-introspection",
                client_secret=introspection_secret,
            )

            identity = await verifier.verify_token(token)

            assert identity is not None
            assert identity.client_id == "incident-worker"
            assert identity.subject is not None
            assert REQUIRED_SCOPE in identity.scopes
            assert str(identity.resource) == resource

    asyncio.run(scenario())
