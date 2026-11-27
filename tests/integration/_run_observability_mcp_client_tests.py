"""Run the production MCP client integration suite against local infrastructure."""

import getpass
import secrets
import subprocess
import sys
import warnings
from pathlib import Path

import httpx
from _otlp_probe import build_redaction_probe

PROJECT_ROOT = Path(__file__).resolve().parents[2]

OTLP_URL = "http://127.0.0.1:4318/v1/logs"
OTLP_USERNAME = "incident-collector"

TEST_FILE = "tests/integration/test_observability_mcp_client_integration.py"

WORKER_SECRET_FILE = (
    Path.home()
    / ".config"
    / "ai-incident-commander"
    / "keycloak"
    / "clients"
    / "incident-worker.secret"
)


def read_otlp_password() -> str:
    """Read the local OTLP password without terminal echo."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("OTLP incident-collector password: ")

    if not password:
        raise ValueError("OTLP password is required")

    return password


def submit_probe(trace_id: str, password: str) -> None:
    """Submit a controlled log to the local Alloy endpoint."""
    with httpx.Client(
        timeout=10.0,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        response = client.post(
            OTLP_URL,
            auth=httpx.BasicAuth(OTLP_USERNAME, password),
            json=build_redaction_probe(trace_id),
        )

    if response.status_code != 200:
        raise ValueError(f"OTLP ingestion rejected the probe: HTTP {response.status_code}")

    print("Controlled OTLP log submission: ACCEPTED", flush=True)


def run_integration_tests(trace_id: str) -> int:
    """Run the isolated MCP client integration container."""
    command = [
        "docker",
        "compose",
        "--env-file",
        ".env",
        "-f",
        "compose.integration-tests.yaml",
        "--profile",
        "integration",
        "run",
        "--rm",
        "--no-deps",
        "-T",
        "-e",
        "RUN_OBSERVABILITY_MCP_CLIENT_TESTS=1",
        "-e",
        f"AIC_TEST_MCP_PROBE_TRACE_ID={trace_id}",
        "observability-client-e2e",
        "-v",
        "-s",
        "-p",
        "no:cacheprovider",
        "--tb=short",
        TEST_FILE,
    ]

    with WORKER_SECRET_FILE.open("rb") as secret_stream:
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            stdin=secret_stream,
            check=False,
        )

    return result.returncode


def main() -> int:
    """Prepare controlled test data and propagate the test exit status."""
    if not WORKER_SECRET_FILE.is_file():
        print(
            "OAuth worker secret file is missing.",
            file=sys.stderr,
        )
        return 1

    try:
        trace_id = secrets.token_hex(16)

        password = read_otlp_password()
        try:
            submit_probe(trace_id, password)
        finally:
            del password

        print(f"Controlled probe trace ID: {trace_id}", flush=True)

        return run_integration_tests(trace_id)

    except (getpass.GetPassWarning, EOFError):
        print(
            "Secure interactive password input is unavailable.",
            file=sys.stderr,
        )
        return 1

    except httpx.HTTPError:
        print(
            "OTLP transport request failed.",
            file=sys.stderr,
        )
        return 1

    except OSError:
        print(
            "Required local file or Docker command is unavailable.",
            file=sys.stderr,
        )
        return 1

    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("\nIntegration test execution interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
