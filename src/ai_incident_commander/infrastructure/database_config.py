"""Database connection configuration for infrastructure adapters."""

import os
from dataclasses import dataclass, field
from typing import Self

from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError


class DatabaseConfigurationError(ValueError):
    """Raised when the database connection configuration is invalid."""


@dataclass(frozen=True, slots=True)
class DatabaseConfig:
    """Validated PostgreSQL connection configuration."""

    url: URL = field(repr=False)

    @classmethod
    def from_environment(cls) -> Self:
        """Read and validate DATABASE_URL from the process environment."""
        raw_url = os.environ.get("DATABASE_URL")

        if raw_url is None or not raw_url.strip():
            raise DatabaseConfigurationError("DATABASE_URL environment variable is required.")

        try:
            parsed_url = make_url(raw_url)
        except ArgumentError:
            raise DatabaseConfigurationError("DATABASE_URL has an invalid format.") from None

        if parsed_url.drivername != "postgresql+psycopg":
            raise DatabaseConfigurationError("DATABASE_URL must use the postgresql+psycopg driver.")

        if not all(
            (
                parsed_url.host,
                parsed_url.database,
                parsed_url.username,
                parsed_url.password,
            )
        ):
            raise DatabaseConfigurationError(
                "DATABASE_URL must include host, database, username, and password."
            )

        return cls(url=parsed_url)
