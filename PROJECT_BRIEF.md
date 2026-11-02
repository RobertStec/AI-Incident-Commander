# AI Incident Commander

## 1. Project Vision

AI Incident Commander is a production-oriented agentic AI system designed to assist with the investigation, diagnosis and resolution of software production incidents.

The project is intended to demonstrate advanced AI Engineering and Software Engineering skills using:

- LangGraph,
- LangChain,
- Retrieval-Augmented Generation,
- Model Context Protocol,
- FastAPI,
- PostgreSQL,
- pgvector,
- Redis,
- Docker,
- LangSmith,
- CI/CD,
- cloud deployment.

The system should not behave as a simple chatbot.

It should operate as a stateful incident-response workflow capable of collecting evidence, coordinating specialized agents, generating hypotheses, planning remediation and executing approved actions through MCP servers.

---

## 2. Target Level

The project must represent at least:

**Strong Mid / Mid+ AI Engineering level**

with selected elements approaching:

**Senior-level system architecture**

The project should demonstrate:

- architectural decision making,
- non-trivial LangGraph orchestration,
- advanced RAG,
- custom MCP servers and clients,
- persistence,
- security,
- observability,
- testing,
- evaluation,
- CI/CD,
- production deployment.

---

## 3. Business Problem

Production incidents are often investigated manually by engineers who must gather information from multiple systems:

- application logs,
- infrastructure metrics,
- deployment history,
- source repositories,
- runbooks,
- previous incidents,
- monitoring systems,
- ticketing systems.

This process is slow and requires repeatedly switching between tools.

AI Incident Commander should coordinate these sources and assist engineers in answering questions such as:

- What happened?
- When did the incident start?
- Which services are affected?
- Did a recent deployment introduce the problem?
- What evidence supports the suspected root cause?
- Has a similar incident happened before?
- What remediation steps are recommended?
- Is rollback appropriate?
- Did the remediation resolve the incident?

---

## 4. Primary Use Case

Example incident:

```text
After the latest deployment, API latency increased significantly
and the number of HTTP 500 responses rose to 15%.
```

The system should:

1. receive the incident,
2. classify severity and affected services,
3. create an investigation plan,
4. collect evidence from multiple sources,
5. analyze logs,
6. analyze metrics,
7. inspect recent deployments,
8. retrieve relevant historical knowledge through RAG,
9. generate possible root-cause hypotheses,
10. evaluate evidence supporting each hypothesis,
11. propose remediation actions,
12. request Human-in-the-Loop approval when required,
13. execute approved operations through MCP,
14. verify the result,
15. generate an incident report or postmortem.

---

## 4.1 Demo Incident Environment

The project should include a controlled demo environment called **Incident Lab**.

Incident Lab will simulate a small production system and provide realistic operational data for the AI Incident Commander.

The purpose of this environment is to make incident investigation deterministic, reproducible and testable without requiring access to a real production system.

Initial demo architecture may contain several services, for example:

```text
API Gateway
    ↓
Orders Service
    ↓
PostgreSQL

Users Service

Payments Service
```

The environment should generate:

- application logs,
- HTTP request logs,
- latency metrics,
- error-rate metrics,
- deployment history,
- service health information,
- alerts.

The project should support reproducible incident scenarios such as:

```text
Scenario 1:
Deployment introduces HTTP 500 errors.

Scenario 2:
Database latency increases and causes API slowdown.

Scenario 3:
One service becomes unavailable.

Scenario 4:
A configuration change causes authentication failures.

Scenario 5:
A memory or resource problem gradually increases latency.
```

Each scenario should have a known root cause.

This allows the system to evaluate whether the AI investigation correctly identifies:

- the affected service,
- the relevant evidence,
- the probable root cause,
- the appropriate remediation.

Incident Lab should also act as the initial backend for MCP servers.

For example:

```text
Incident Lab
      │
      ├── logs
      ├── metrics
      ├── deployments
      └── service state
            │
            ▼
    MCP Servers
            │
            ▼
AI Incident Commander
```

Later, the same MCP interfaces could be adapted to real external systems without changing the core LangGraph incident workflow.

The demo environment should remain isolated from the AI application itself so that MCP acts as the integration boundary between the incident system and operational infrastructure.


## 5. Functional Requirements

### Incident Management

The application should support:

- creating incidents,
- assigning incident IDs,
- incident status tracking,
- severity classification,
- affected service identification,
- investigation history,
- timeline tracking,
- incident resolution,
- postmortem generation.

### AI Investigation

The system should be able to:

- create investigation plans,
- decompose complex problems,
- run investigation tasks in parallel,
- collect evidence,
- correlate evidence from multiple sources,
- generate hypotheses,
- rank hypotheses,
- identify missing evidence,
- recommend next investigation steps.

### Human-in-the-Loop

Actions capable of changing infrastructure or production state must require explicit approval.

Examples:

- rollback deployment,
- restart service,
- scale service,
- execute remediation commands.

Read-only investigation operations should normally execute without approval.

---

## 6. LangGraph Architecture

LangGraph is the central orchestration layer.

The system should not be implemented as one large agent loop.

The target architecture should use multiple graphs and subgraphs.

Initial conceptual architecture:

```text
Main Incident Graph
        │
        ├── Incident Classification
        │
        ├── Investigation Planner
        │
        ├── Investigator Subgraph
        │       ├── Logs Investigator
        │       ├── Metrics Investigator
        │       ├── Deployment Investigator
        │       └── RAG Investigator
        │
        ├── Evidence Aggregator
        │
        ├── Hypothesis Generator
        │
        ├── Hypothesis Verifier
        │
        ├── Remediation Subgraph
        │
        ├── Human Approval
        │
        ├── Action Executor
        │
        └── Verification Subgraph
```

LangGraph features should include:

- typed state,
- conditional edges,
- parallel execution,
- subgraphs,
- `Command` routing,
- `interrupt()`,
- durable execution,
- persistent checkpoints,
- retry strategies,
- controlled error handling,
- structured outputs.

---

## 7. MCP Architecture

Model Context Protocol is a core technology of the project.

The project should include both:

- MCP clients,
- custom MCP servers.

Initial MCP servers:

```text
mcp-observability
mcp-deployment
mcp-repository
mcp-incident
```

### Observability MCP

Possible tools:

```text
search_logs
get_recent_errors
query_metrics
get_service_health
get_active_alerts
```

Possible resources:

```text
logs://service/{service}
metrics://service/{service}
alerts://incident/{incident_id}
```

### Deployment MCP

Possible tools:

```text
get_current_release
get_previous_release
get_deployment_history
restart_service
rollback_release
scale_service
```

Write operations must integrate with Human-in-the-Loop approval.

### Repository MCP

Possible capabilities:

```text
get_recent_commits
get_commit_diff
get_changed_files
get_pull_request
search_repository
```

### Incident MCP

Possible capabilities:

```text
create_incident
update_incident
add_timeline_event
add_evidence
close_incident
```

The project should demonstrate:

- MCP tools,
- MCP resources,
- MCP prompts where justified,
- multiple MCP servers,
- MCP client lifecycle management,
- error handling,
- timeouts,
- authentication where applicable.

---

## 8. RAG Architecture

RAG should act as an evidence source for incident investigation rather than a simple document-chat feature.

Knowledge sources may include:

- runbooks,
- previous incidents,
- postmortems,
- service documentation,
- architecture documentation,
- deployment procedures,
- rollback procedures,
- operational notes.

Target RAG pipeline:

```text
Incident Query
      ↓
Query Analysis
      ↓
Query Rewriting / Decomposition
      ↓
Metadata Filtering
      ↓
Candidate Retrieval
      ↓
Reranking
      ↓
Relevance Filtering
      ↓
Evidence Selection
      ↓
Source Attribution
```

Planned capabilities:

- embeddings,
- chunking,
- metadata-aware retrieval,
- multi-stage retrieval,
- query rewriting,
- query decomposition,
- reranking,
- relevance thresholds,
- source attribution,
- evidence scoring,
- controlled no-answer behavior,
- RAG evaluation.

PostgreSQL with pgvector should initially be used as the vector store.

---

## 9. Evidence Model

A key design concept is that agents should operate on explicit evidence rather than unrestricted free-form reasoning.

Evidence should contain information such as:

```text
evidence_id
incident_id
source_type
source_reference
content
timestamp
relevance_score
confidence
collector
metadata
```

Possible evidence sources:

```text
logs
metrics
deployments
repository
RAG
alerts
human input
```

Hypotheses should reference the evidence that supports or contradicts them.

---

## 10. Persistence

The system should persist:

- users,
- incidents,
- incident timeline,
- LangGraph checkpoints,
- evidence,
- hypotheses,
- remediation plans,
- approvals,
- action history,
- RAG documents,
- RAG chunks,
- audit events.

Initial persistence technologies:

- PostgreSQL,
- pgvector,
- Redis.

---

## 11. Security

Security must be designed from the beginning.

The system should eventually include:

- authentication,
- authorization,
- user isolation,
- role-based permissions,
- secure sessions,
- rate limiting,
- input validation,
- secure MCP communication,
- tool permission boundaries,
- Human-in-the-Loop for destructive actions,
- audit logging,
- secrets management,
- safe error responses.

The principle of least privilege should be applied to MCP tools and cloud permissions.

---

## 12. Observability

The application should provide observability for both application code and agent execution.

Planned areas:

- structured logging,
- request correlation IDs,
- incident correlation IDs,
- LangGraph execution tracing,
- MCP call tracing,
- RAG tracing,
- LLM usage tracking,
- latency tracking,
- error tracking,
- LangSmith integration.

Later stages may introduce:

- OpenTelemetry,
- metrics,
- dashboards,
- alerting.

---

## 13. Testing Strategy

The project should include:

### Unit Tests

For:

- graph nodes,
- routers,
- services,
- tools,
- RAG components,
- MCP handlers,
- validation logic.

### Integration Tests

For:

- PostgreSQL,
- pgvector,
- Redis,
- MCP clients and servers,
- FastAPI endpoints,
- LangGraph persistence.

### Agent Tests

For:

- routing,
- investigation planning,
- evidence aggregation,
- hypothesis generation,
- Human-in-the-Loop,
- remediation workflows.

### RAG Evaluation

Evaluate:

- retrieval quality,
- reranking,
- relevance,
- groundedness,
- source correctness.

### Regression Evaluation

LangSmith datasets and evaluators should be used to prevent quality regressions.

---

## 14. CI/CD

The project should eventually include automated pipelines for:

- unit tests,
- integration tests,
- PostgreSQL tests,
- MCP tests,
- RAG evaluation,
- regression evaluation,
- Docker builds,
- dependency audits,
- static security analysis,
- secret scanning,
- container vulnerability scanning.

Pull Requests should be protected by required quality gates.

---

## 15. Deployment

The final application should be containerized and deployed to a production environment.

Target areas include:

- Docker,
- Docker Compose,
- reverse proxy,
- HTTPS,
- PostgreSQL,
- Redis,
- cloud deployment,
- CI/CD deployment,
- health checks,
- rollback strategy,
- secure secrets delivery.

The exact production architecture will be decided later.

---

## 16. Initial Technology Stack

### Language

```text
Python 3.11+
```

### Agent Framework

```text
LangGraph
LangChain
```

### LLM

```text
OpenAI
```

### MCP

```text
Model Context Protocol
Python MCP SDK
```

### Backend

```text
FastAPI
Pydantic
```

### Persistence

```text
PostgreSQL
pgvector
Redis
```

### AI Observability

```text
LangSmith
```

### Infrastructure

```text
Docker
Docker Compose
GitHub Actions
```

Additional technologies should only be introduced when there is a concrete architectural reason.

---

## 17. Development Principles

The project should follow:

- incremental development,
- separation of concerns,
- typed interfaces,
- explicit state,
- structured outputs,
- configuration through environment variables,
- dependency isolation,
- testability,
- security by design,
- observability by design.

Avoid unnecessary complexity.

Every advanced architectural component should solve a real project requirement.

---

## 18. High-Level Roadmap

### Phase 1 — Foundation

- project requirements,
- architecture,
- development environment,
- repository structure,
- initial FastAPI application.

### Phase 2 — LangGraph Core

- incident state,
- main graph,
- routing,
- investigation planning,
- subgraphs,
- persistence.

### Phase 3 — MCP

- MCP architecture,
- first custom MCP server,
- MCP client,
- multiple MCP servers,
- tool permissions.

### Phase 4 — Advanced RAG

- ingestion,
- embeddings,
- pgvector,
- metadata retrieval,
- reranking,
- evidence model,
- evaluation.

### Phase 5 — Incident Intelligence

- evidence aggregation,
- hypothesis generation,
- hypothesis verification,
- root-cause ranking.

### Phase 6 — Remediation

- remediation planning,
- Human-in-the-Loop,
- MCP action execution,
- verification.

### Phase 7 — Multi-User and Security

- authentication,
- authorization,
- isolation,
- RBAC,
- audit log,
- rate limiting.

### Phase 8 — Evaluation and Testing

- unit tests,
- integration tests,
- MCP tests,
- RAG evaluation,
- LangSmith regression evaluation.

### Phase 9 — Production Engineering

- Docker,
- CI/CD,
- security scanning,
- observability,
- production configuration.

### Phase 10 — Deployment

- cloud infrastructure,
- production deployment,
- health checks,
- rollback,
- smoke tests.

### Phase 11 — Portfolio Release

- final README,
- architecture diagrams,
- documentation,
- release notes,
- tag `v1.0.0`.

---

## 19. Definition of Done

AI Incident Commander can be considered complete when:

- LangGraph coordinates a non-trivial multi-stage incident workflow,
- multiple LangGraph subgraphs are used,
- investigation tasks can execute in parallel,
- persistent graph state works,
- multiple custom MCP servers are implemented,
- the application acts as an MCP client,
- RAG provides traceable incident evidence,
- evidence is linked to generated hypotheses,
- remediation requires approval where appropriate,
- approved remediation can execute through MCP,
- results are automatically verified,
- automated tests cover critical workflows,
- RAG and agent quality are evaluated,
- CI/CD quality gates are active,
- security controls are implemented,
- the application is deployed,
- observability is available,
- production smoke tests pass,
- project documentation is complete,
- GitHub release `v1.0.0` is published.

---

## 20. Project Status

```text
Status: Planning
Target level: Strong Mid / Mid+
Stretch target: Senior-level architecture
```