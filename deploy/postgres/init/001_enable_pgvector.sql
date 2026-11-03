
-- Enable pgvector for the incident_commander database.
-- Executed during initialization of a fresh PostgreSQL data directory.

CREATE EXTENSION IF NOT EXISTS vector;
