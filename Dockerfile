
# syntax=docker/dockerfile:1

# AI Incident Commander — Observability MCP runtime.

# Stage 1: Build the Python application.
FROM python:3.12-slim-bookworm AS builder

# Pin the uv tool version. Do not install uv in the runtime image.
COPY --from=ghcr.io/astral-sh/uv:0.13.8 /uv /uvx /bin/

ENV UV_PYTHON_DOWNLOADS=0 \
    UV_LINK_MODE=copy \
    UV_NO_DEV=1

WORKDIR /app

# Only explicitly allowed files enter the build context.
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

# Verify the lockfile and install the application non-editably.
RUN uv sync --locked --no-dev --no-editable

# Test-only stage: never copied into the production runtime image.
FROM builder AS integration-test

# The builder excludes dev dependencies. Enable them only here.
RUN env -u UV_NO_DEV uv sync --locked --no-editable --group dev

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Execute integration tests without root privileges.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 \
       --no-create-home --shell /usr/sbin/nologin app

USER 10001:10001

# Test sources will be mounted read-only at execution time.
ENTRYPOINT ["/app/.venv/bin/python", "-m", "pytest"]

# Stage 3: Minimal runtime.
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

# Use a dedicated unprivileged identity.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 \
       --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

# Copy only the installed virtual environment.
COPY --from=builder /app/.venv /app/.venv

USER 10001:10001

# Internal application port. Publishing is controlled by Compose.
EXPOSE 8000

CMD ["uvicorn", \
     "ai_incident_commander.application.observability_mcp_runtime:create_app", \
     "--factory", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--no-access-log"]
