# AI Incident Commander — Session Handoff

> **Checkpoint:** 2026-11-15 — po ukończeniu kontraktu Secure MCP Executor i przygotowaniu dokumentacji `apv:v1 → apv:v2`; **przed końcową regresją i Git**.
> **Źródła:** `PROJECT_BRIEF.md` (wizja), `PROJECT_PROGRESS.md` (kamienie milowe), `README.md` (portfolio), `docs/adr/0001-mcp-bound-approval-policy-versioning.md` (decyzja).
> **Priorytet:** rzeczywiste pliki repozytorium i aktualne wyniki poleceń > niniejszy checkpoint. Stan Git i kompletność kopii dokumentów wymagają sprawdzenia.

## 1. Punkt wznowienia

- **Technicznie ukończony etap:** `1.7.8.11.42.7.5.11` — `SecureMcpExecutor` Protocol + `McpInvocationResult` (`ACKNOWLEDGED`, `REJECTED`, `UNKNOWN`), **17 passed**; nie ma implementacji wykonującej MCP.
- **MCP-bound Bootstrap:** `mcp_approval_workflow_lifespan()` wymusza zaufane, spójne `TrustedMcpActionBindings` dla Approval Request Creation i Guard; **25 passed** (12 legacy + 13 nowych).
- **Ostatnia pełna regresja:** **1400 passed**, **0 failed**, 29,85 s (2026-11-15, `RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1`). Ta regresja została wykonana **przed** dodaniem najnowszych testów Composition Root i kontraktu Executora; należy ją powtórzyć.
- **Ostatnia jakość:** Ruff lint **PASSED**, Ruff format **114 plików**, Mypy **52 pliki**, bez błędów (po dodaniu Secure MCP Executor Contract).
- **Alembic/PostgreSQL:** `e62b4f0c91ad (head)` zastosowane na lokalnej bazie; 6 testów schematu zaliczonych. Nie wykonywano destrukcyjnego downgrade.
- **Git:** ostatni potwierdzony commit/push: **`7d49058`** (`security: remove unverified remediation dispatch reservation`), wtedy `main...origin/main` bez zmian. **Wszystkie późniejsze zmiany, w tym `apv:v2`, mogą nadal być niezatwierdzone — sprawdzić status przed commitem.**
- **Dokumentacja:** `README.md` i ADR-0001 przygotowano jako pliki do umieszczenia w repo; niniejsze dwa dokumenty checkpointu są aktualizowane. **Nie zakładać, że Git już je śledzi.**
- **Następny krok:** wstawić dokumenty, uruchomić końcową regresję i jakość, sprawdzić `git status` z nowymi plikami, uzgodnić staging/commit/push. **Następnie:** krótki audyt Foundation i rozpoczęcie `Phase 2.0 — LangGraph Core`.

## 2. Najważniejsze kontrakty bezpieczeństwa

- **Approval → Execution:** `ApprovalRequestCreationService` tworzy request z zaufanego Preflight i `afp:v2`; `ApprovalApplicationService` zapisuje decyzję człowieka; Guard czyta utrwalone `APPROVED` i ponawia Preflight / porównanie policy/fingerprint/target.
- **Legacy vs MCP-bound:** `apv:v1` identyfikuje katalog akcji i pozostaje do odczytu historycznego. `apv:v2` dodaje `binding_version` z `TrustedMcpActionBindings`. Jawne MCP Preflight / request / Guard wymagają `apv:v2`; stare żądanie nie może przejść MCP-bound Guard. Testy odmów po zmianie `tool_name`, `server_id`, `resource_id` i `REJECTED` są zielone.
- **Composition Root:** `mcp_approval_workflow_lifespan()` łączy ten sam rejestr bindings z Request Service i Guard; dotychczasowe wejście legacy pozostaje oddzielne. Nadal trzeba kontrolować, kto może tworzyć privileged executor i jakie poświadczenia dostaje.
- **Execution Claim / Lifecycle:** PostgreSQL `UNIQUE(plan_id, step_id)`, `UNIQUE(request_id)`, `UNIQUE(claim_id)` i transakcyjne rechecks; `EXECUTING → SUCCEEDED / FAILED / UNKNOWN`. `RemediationExecutionRecoveryService` odzyskuje jedynie stary claim **bez istniejącego execution**, bez replay.
- **Trusted Dispatch:** `RemediationTrustedDispatchService.reserve_for_step(request_id, step)` → świeży Guard → `reserve_verified_once()`; PostgreSQL sprawdza execution / claim / approval / fingerprint / policy i `UNIQUE(execution_id)`. Dawne niezabezpieczone `reserve_once()` zostało usunięte (commit `7d49058`). `ReservedVerifiedDispatch` i `VerifiedExecutionContext` nie są capability.
- **Secure MCP Executor Contract:** tylko port `execute_for_step(request_id, step)` i model wyniku (`ACKNOWLEDGED`, `REJECTED`, `UNKNOWN`). Brak klienta, serwera, transportu lub faktycznych działań; ACK nie dowodzi remediation success.
- **Ryzyka przed realnym MCP:** alias `server_id` nie zabezpiecza niejawnej zmiany endpointu/semantyki; wymagane pinning i wersjonowanie konfiguracji, downstream idempotency, resource preconditions, reconciliation `UNKNOWN`, bezpieczne wznowienia LangGraph i produkcyjne auth/RBAC. **Brak dokładnie jednorazowego efektu zewnętrznego.**

## 3. Co zostało zweryfikowane

- Lokalny upgrade Alembic `c4f8a2d7e951 → e62b4f0c91ad` i `alembic current = e62b4f0c91ad (head)`.
- PostgreSQL: **6** testów schematu `apv:v2` passed; **37** testów approval/Guard/claim/execution/dispatch passed.
- Po korekcie dwóch starych testów traktujących `apv:v2` jako invalid: **91** testów modeli passed; pełna regresja **1400 passed**.
- Po pełnej regresji: **25** testów Bootstrap i **17** testów kontraktu Executora passed; Ruff/Mypy bez błędów.
- Testy potwierdzają kontrakty i ścieżki PostgreSQL, **nie** live MCP, LangGraph, produkcyjne RBAC lub exactly-once.

## 4. Dokumentacja portfolio (obowiązkowa przed Phase 2)

- `README.md`: bardzo widoczna sekcja **Architecture evolution: `apv:v1` → `apv:v2`**, link do ADR i jasne rozdzielenie funkcji zaimplementowanych od planowanych.
- `docs/adr/0001-mcp-bound-approval-policy-versioning.md`: przyczyna, podjęta decyzja, migracja `e62b4f0c91ad`, alternatywy, kompromisy, testy i otwarte ryzyka.
- **Uczciwe framing:** projekt zaczął się od zera; wcześniejsze `apv:v1` nie było z góry zaplanowaną symulacją ewolucji wymagań. Przedstawiamy rzeczywiste opóźnione odkrycie potrzeby zabezpieczenia mapowań MCP i bezpieczną migrację.
- Potwierdzić, że README i ADR znajdują się w repo i zostaną uwzględnione w uzgodnionym commicie.

## 5. Kolejność dalszych czynności

1. Po wgraniu dwóch plików checkpointu sprawdzić ich diff oraz status Git: `git status --short`, `git diff --stat`, `git diff --check`; sprawdzić **untracked** (w tym migracje, dokumentację i nowe testy).
2. Końcowa regresja przy uruchomionym PostgreSQL/Docker: `RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 uv run --env-file .env pytest -q`; Ruff lint/format oraz Mypy.
3. Uzyskać kontrolę pełnej listy zmian, stage **tylko uzgodnione pliki**, sprawdzić `git diff --cached --check`, `git diff --cached --stat`, `git status --short`, commit, push, `git status -sb`.
4. Po potwierdzonym clean Git zweryfikować minimalne wymagania Foundation (szczególnie FastAPI) i rozpocząć **Phase 2.0 — LangGraph Core**, zamiast dalej rozbudowywać gałąź Remediation bez grafu.
5. Przed zmianą istniejącego pliku użytkownik przekazuje **cały aktualny plik**; małe kroki, najwyżej **8 plików testowych** w partii. Nie wprowadzać teraz rzeczywistych mutujących operacji MCP.

### Polecenia weryfikacyjne

```bash
RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 \
uv run --env-file .env pytest -q
uv run ruff check src/ tests/ migrations/versions/
uv run ruff format --check src/ tests/ migrations/versions/
uv run mypy src/ai_incident_commander/
git status --short
git diff --stat
git diff --check
```
