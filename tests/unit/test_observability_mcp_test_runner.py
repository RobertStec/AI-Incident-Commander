"""Unit tests for the local Observability MCP integration runner."""

import getpass
import importlib
import subprocess
from pathlib import Path
from types import ModuleType
from typing import BinaryIO
from unittest.mock import MagicMock, Mock

import httpx
import pytest


@pytest.fixture
def runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> ModuleType:
    integration_dir = Path(__file__).resolve().parents[1] / "integration"

    monkeypatch.syspath_prepend(str(integration_dir))

    module = importlib.import_module("_run_observability_mcp_client_tests")

    secret_file = tmp_path / "worker.secret"
    secret_file.write_bytes(b"synthetic-worker-secret\n")

    monkeypatch.setattr(
        module,
        "WORKER_SECRET_FILE",
        secret_file,
    )

    return module


def test_runner_rejects_missing_worker_secret(
    runner: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner.WORKER_SECRET_FILE.unlink()

    read_password = Mock()
    submit_probe = Mock()
    run_tests = Mock()

    monkeypatch.setattr(runner, "read_otlp_password", read_password)
    monkeypatch.setattr(runner, "submit_probe", submit_probe)
    monkeypatch.setattr(runner, "run_integration_tests", run_tests)

    assert runner.main() == 1

    read_password.assert_not_called()
    submit_probe.assert_not_called()
    run_tests.assert_not_called()

    assert "OAuth worker secret file is missing." in capsys.readouterr().err


@pytest.mark.parametrize(
    ("password", "error", "expected_code"),
    [
        pytest.param(
            "",
            None,
            1,
            id="empty-password",
        ),
        pytest.param(
            None,
            getpass.GetPassWarning(),
            1,
            id="insecure-password-input",
        ),
        pytest.param(
            None,
            EOFError(),
            1,
            id="unexpected-eof",
        ),
        pytest.param(
            None,
            KeyboardInterrupt(),
            130,
            id="keyboard-interrupt",
        ),
    ],
)
def test_runner_aborts_on_password_input_failure(
    runner: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    password: str | None,
    error: BaseException | None,
    expected_code: int,
) -> None:
    submit_probe = Mock()
    run_tests = Mock()

    monkeypatch.setattr(
        runner.getpass,
        "getpass",
        Mock(return_value=password, side_effect=error),
    )
    monkeypatch.setattr(runner, "submit_probe", submit_probe)
    monkeypatch.setattr(runner, "run_integration_tests", run_tests)

    assert runner.main() == expected_code

    submit_probe.assert_not_called()
    run_tests.assert_not_called()


@pytest.mark.parametrize(
    "status_code",
    [
        pytest.param(401, id="otlp-rejected"),
        pytest.param(None, id="otlp-transport-failure"),
    ],
)
def test_runner_aborts_on_otlp_failure(
    runner: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status_code: int | None,
) -> None:
    run_tests = Mock()

    http_client = MagicMock()
    http_client.__enter__.return_value = http_client

    if status_code is None:
        http_client.post.side_effect = httpx.ConnectError("Synthetic transport failure")
    else:
        http_client.post.return_value = httpx.Response(status_code)

    monkeypatch.setattr(
        runner,
        "read_otlp_password",
        Mock(return_value="synthetic-otlp-password"),
    )
    monkeypatch.setattr(
        runner.httpx,
        "Client",
        Mock(return_value=http_client),
    )
    monkeypatch.setattr(runner, "run_integration_tests", run_tests)

    assert runner.main() == 1

    http_client.post.assert_called_once()
    run_tests.assert_not_called()

    captured = capsys.readouterr()

    assert "ACCEPTED" not in captured.out
    assert "synthetic-otlp-password" not in captured.out
    assert "synthetic-otlp-password" not in captured.err


@pytest.mark.parametrize(
    ("returncode", "expected_code"),
    [
        pytest.param(0, 0, id="pytest-success"),
        pytest.param(1, 1, id="pytest-failure"),
        pytest.param(5, 5, id="pytest-no-tests-collected"),
        pytest.param(None, 1, id="docker-unavailable"),
    ],
)
def test_runner_propagates_execution_status(
    runner: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int | None,
    expected_code: int,
) -> None:
    submit_probe = Mock()

    monkeypatch.setattr(
        runner,
        "read_otlp_password",
        Mock(return_value="synthetic-otlp-password"),
    )
    monkeypatch.setattr(runner, "submit_probe", submit_probe)

    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        stdin: BinaryIO,
        check: bool,
    ) -> subprocess.CompletedProcess[bytes]:
        submit_probe.assert_called_once()

        assert command[:2] == ["docker", "compose"]
        assert "observability-client-e2e" in command
        assert "--rm" in command
        assert "--no-deps" in command
        assert "-T" in command

        trace_id = submit_probe.call_args.args[0]

        assert f"AIC_TEST_MCP_PROBE_TRACE_ID={trace_id}" in command

        assert cwd == runner.PROJECT_ROOT
        assert check is False

        assert stdin.read() == b"synthetic-worker-secret\n"

        assert "synthetic-worker-secret" not in " ".join(command)
        assert "synthetic-otlp-password" not in " ".join(command)

        if returncode is None:
            raise FileNotFoundError("Docker command unavailable")

        return subprocess.CompletedProcess(
            command,
            returncode,
        )

    run_process = Mock(side_effect=fake_run)

    monkeypatch.setattr(
        runner.subprocess,
        "run",
        run_process,
    )

    assert runner.main() == expected_code

    run_process.assert_called_once()
    assert run_process.call_args.kwargs["stdin"].closed
