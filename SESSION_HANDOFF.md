# AI Incident Commander — Session Handoff

> **Checkpoint:** 2026-11-14, po pełnej regresji **Durable MCP Dispatch Reservation** (`1.7.8.11.42.5`).
> **Cel:** bezpieczne wznowienie pracy bez odtwarzania długiej historii rozmowy.
> **Dokumenty:** `PROJECT_BRIEF.md` — wymagania; `PROJECT_PROGRESS.md` — architektura i kamienie milowe.
> **Priorytet źródeł:** rzeczywiste pliki repozytorium i wyniki wykonanych poleceń > ten checkpoint.

## 1. Dokładny punkt wznowienia

- **Bieżący etap:** `1.7.8.11.42.5` — Durable MCP Dispatch Reservation, zakończony technicznie i zweryfikowany; **bieżące zmiany nie mają jeszcze potwierdzonego commita/pushu**.
- **Pełna regresja:** `RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 uv run --env-file .env pytest -q` → **1225 passed w 19,54 s** (2026-11-14).
- **Jakość:** Ruff lint PASSED, Ruff format **99 plików**, Mypy **49 plików źródłowych**, bez błędów.
- **Teraz:** podmienić oba dokumenty w repozytorium, sprawdzić Git, staging, commit i push. **Nie zaczynać wdrażania MCP**, dopóki kamień milowy nie zostanie zamknięty w Git.
- **Następny etap:** `1.7.8.11.42.6` — Trusted Dispatch Service; najpierw zaprojektować bezpieczny kontrakt wiążący zatwierdzony scope, konkretny target, trwałe EXECUTING i pojedynczy dispatch. Nie dodawać automatycznego ponawiania MCP.

## 2. Git, PostgreSQL i testy

- **Ostatni potwierdzony commit/push:** `1ebfdda` — `feat: implement trusted remediation execution crash recovery`; `main` zsynchronizowana z `origin/main`, clean **bezpośrednio po tym commicie**. Zmiany dispatchu po tym commicie nie są jeszcze zatwierdzone; **aktualnego `git status` nie potwierdzono**.
- **Alembic:** `f4d2a6b8c901` (Claims) → `a31e5d79c204` (Execution Lifecycle) → **`c4f8a2d7e951` (Dispatch Reservations)**. Lokalny `alembic current`: `c4f8a2d7e951 (head)`; test nowego schematu **1 passed**.
- **Wybrane testy lokalne:** `tests/unit/test_approval_execution_guard.py` → **18 passed**; `tests/unit/test_remediation_dispatch.py` → **13 passed**; `tests/unit/test_remediation_dispatch_repository.py` → **7 passed**; `tests/integration/test_postgres_remediation_dispatch_repository_integration.py` → **13 passed** (w tym 2 scenariusze współbieżności).
- Pełna regresja 1225 obejmowała testy opt-in PostgreSQL i zgodności schematów. Nie należy interpretować jej jako dowodu skutków zewnętrznych MCP: wywołania MCP jeszcze nie zaimplementowano.

## 3. Zmiany po `1ebfdda` — potwierdzić w `git status`

**Zmodyfikowane (według etapów pracy):**

- `src/ai_incident_commander/application/approval_execution_guard.py` — `VerifiedExecutionContext` i `verify_execution_context_for_step()`; zachowane starsze API Guard.
- `tests/unit/test_approval_execution_guard.py` — testy zaufanego scope i `ResolvedTarget` z jednego Preflight.

**Dodane (według etapów pracy):**

- `src/ai_incident_commander/domain/remediation_dispatch.py` — niezmienny `RemediationDispatch(execution_id, reserved_at, dispatch_id)`.
- `src/ai_incident_commander/application/remediation_dispatch_repository.py` — port `reserve_once()` / `get_by_execution_id()` i odmowy.
- `src/ai_incident_commander/infrastructure/remediation_dispatch_tables.py` — tabela `remediation_dispatches`.
- `migrations/versions/c4f8a2d7e951_create_remediation_dispatches.py` — migracja Alembic.
- `src/ai_incident_commander/infrastructure/postgres_remediation_dispatch_repository.py` — adapter PostgreSQL.
- `tests/unit/test_remediation_dispatch.py` i `tests/unit/test_remediation_dispatch_repository.py`.
- `tests/integration/test_remediation_dispatch_schema_integration.py` i `tests/integration/test_postgres_remediation_dispatch_repository_integration.py`.
- `PROJECT_PROGRESS.md` i `SESSION_HANDOFF.md` — niniejsza aktualizacja dokumentacji; przed commitem sprawdzić status obu plików.

## 4. Kluczowe niezmienniki bezpieczeństwa

- **Zaufany zakres:** `ApprovalExecutionGuard` weryfikuje persistowane `APPROVED`, aktualny Preflight, Action Fingerprint i wersję polityki. `VerifiedExecutionContext(scope, target)` zwraca scope i konkretny `ResolvedTarget` z **tego samego Preflight**. To nie jest token wykonania.
- **Trwałe wykonanie:** `ExecutionClaim` rezerwuje krok, `RemediationExecution` utrwala próbę ze stanem `EXECUTING → SUCCEEDED / FAILED / UNKNOWN`. `EXECUTING` i `UNKNOWN` po restarcie **nie pozwalają** automatycznie ponowić efektu zewnętrznego.
- **Trusted Crash Recovery:** oddzielny serwis może odzyskać tylko istniejący claim **bez rozpoczętego wykonania**, po świeżej weryfikacji Guard i transakcyjnym sprawdzeniu wieku claimu / scope. Został zatwierdzony w commicie `1ebfdda`.
- **Durable Dispatch Reservation:** `PostgresRemediationDispatchRepository.reserve_once(execution_id)` blokuje wiersz execution (`SELECT ... FOR UPDATE`), wymaga statusu `EXECUTING`, odmawia duplikatu, zapisuje `reserved_at` według zegara PostgreSQL i commituje przed zwróceniem wyniku. `UNIQUE(execution_id)` wymusza maksymalnie jedną rezerwację. Wyścigi reserve/reserve i reserve/outcome przetestowane.
- **Granica uprawnień:** samo `execution_id`, `VerifiedExecutionContext`, zapis `EXECUTING` lub istniejąca rezerwacja **nie są zgodą na wywołanie MCP**. Port rezerwacji nie weryfikuje fingerprintu, tożsamości zasobu ani autoryzacji wywołującego. Przyszły Trusted Dispatch Service musi stworzyć tę granicę.
- **Niepewny wynik:** po crashu lub timeout nie wykonywać automatycznego retry; zaplanować idempotency/preconditions u dostawcy oraz reconciliation. PostgreSQL gwarantuje unikalność rezerwacji, nie exactly-once skutku zewnętrznego ani braku TOCTOU po Preflight.
- **Auth:** brak produkcyjnego RBAC/auth; nigdy nie wprowadzać domyślnego `allow-all`.

## 5. Następne polecenia i sposób pracy

1. Po podmianie dokumentów: `git status --short`, `git diff --stat`, `git diff --check` — uwzględnić `??`, których zwykły `git diff --stat` nie wyświetli.
2. Po sprawdzeniu listy dodać **tylko uzgodnione pliki**, uruchomić `git diff --cached --check`, `git diff --cached --stat`, `git status --short`; następnie commit/push i `git status -sb`.
3. Rozpocząć projekt Trusted Dispatch Service małymi krokami. **Przed zmianą istniejącego pliku użytkownik przesyła jego całą aktualną wersję**; nie zgadywać implementacji. Maksymalnie 8 plików testowych w partii.
4. `PROJECT_PROGRESS.md` aktualizować tylko po kamieniach milowych; `SESSION_HANDOFF.md` odświeżać przy większych zmianach lub przed zmianą konwersacji.

**Powtarzalne kontrole:**

```bash
uv run ruff check src/ tests/ migrations/versions/
uv run ruff format --check src/ tests/ migrations/versions/
uv run mypy src/ai_incident_commander/
RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 uv run --env-file .env pytest -q
```
