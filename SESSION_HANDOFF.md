# AI Incident Commander — Session Handoff

> **Checkpoint:** 2026-11-14, po pełnej regresji **Verified Dispatch Authorization & Trusted Dispatch Service** (`1.7.8.11.42.6`).
> **Cel:** bezpieczne wznowienie pracy bez odtwarzania długiej historii rozmowy.
> **Dokumenty:** `PROJECT_BRIEF.md` — wymagania; `PROJECT_PROGRESS.md` — decyzje architektoniczne i kamienie milowe.
> **Priorytet źródeł:** rzeczywisty kod i wykonane polecenia > niniejszy checkpoint; stan repozytorium weryfikować w Git.

## 1. Dokładny punkt wznowienia

- **Bieżący etap:** `1.7.8.11.42.6` — Trusted Dispatch Service wraz z transakcyjną Verified Dispatch Authorization, **ukończony technicznie i zweryfikowany**. Commit/push aktualnych zmian: **jeszcze niepotwierdzone**.
- **Pełna regresja:** `RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 uv run --env-file .env pytest -q` → **1276 passed w 28,77 s** (2026-11-14, lokalny PostgreSQL).
- **Jakość:** Ruff lint PASSED; Ruff format **102 pliki**; Mypy **50 plików źródłowych**, bez błędów.
- **Teraz:** zastąpić lokalne `PROJECT_PROGRESS.md` i `SESSION_HANDOFF.md` nowymi wersjami; przejrzeć Git (`status`, `diff`, `diff --check`), dodać tylko uzgodnione pliki, wykonać kontrolę staging, commit, push i `git status -sb`.
- **Kolejny obszar po commicie:** **Secure MCP Execution Boundary** — najpierw zamknięcie alternatywnej rezerwacji `reserve_once()`, ograniczenie dostępu do adapterów i projekt pojedynczego, niemożliwego do replay wywołania. Jeszcze **bez rzeczywistego MCP**.

## 2. Git, PostgreSQL i potwierdzone testy

- **Ostatni potwierdzony commit/push:** `4aaa1ff` — `feat: implement durable remediation MCP dispatch reservations`; `main` zsynchronizowana z `origin/main`, working tree czysty **bezpośrednio po tym commicie**. Stan bieżącego working tree po pracach `1.7.8.11.42.6` wymaga sprawdzenia.
- **Alembic:** `f4d2a6b8c901` (Claims) → `a31e5d79c204` (Execution Lifecycle) → `c4f8a2d7e951` (Dispatch Reservations, ostatnia potwierdzona lokalna `head`). Etap Trusted Dispatch Service **nie wprowadza nowej migracji**.
- **Wybrane testy:** `tests/unit/test_remediation_verified_dispatch_repository.py` → **8 passed**; `tests/unit/test_remediation_trusted_dispatch_service.py` → **15 passed**; `tests/integration/test_postgres_remediation_dispatch_repository_integration.py` → **32 passed** (w tym wyścigi verified reserve/verified reserve i verified reserve/outcome); `tests/integration/test_approval_execution_guard_integration.py` → **29 passed** (w tym 9 nowych scenariuszy serwisu).
- **Pełna regresja:** **1276 passed** obejmuje testy jednostkowe, integracyjne oraz opt-in PostgreSQL i schematów. Nie testuje faktycznych wywołań zewnętrznych MCP, których jeszcze nie zaimplementowano.

## 3. Zmiany po `4aaa1ff` — potwierdzić w `git status`

**Zmodyfikowane według dotychczasowych etapów:**

- `src/ai_incident_commander/application/remediation_dispatch_repository.py` — port `RemediationVerifiedDispatchRepository`, kontrakt `reserve_verified_once()` i odmowy.
- `src/ai_incident_commander/infrastructure/postgres_remediation_dispatch_repository.py` — transakcyjny Verified Dispatch; stare `reserve_once()` tymczasowo zachowane.
- `tests/integration/test_postgres_remediation_dispatch_repository_integration.py` — scenariusze zgodności scope, persisted approval, statusów i współbieżności.
- `tests/integration/test_approval_execution_guard_integration.py` — pełny przepływ Trusted Dispatch Service na PostgreSQL oraz cleanup `dispatch → execution → claim → decision → request`.

**Nowe według dotychczasowych etapów:**

- `src/ai_incident_commander/application/remediation_trusted_dispatch_service.py` — `RemediationTrustedDispatchService` i `ReservedVerifiedDispatch`.
- `tests/unit/test_remediation_verified_dispatch_repository.py` — testy kontraktu.
- `tests/unit/test_remediation_trusted_dispatch_service.py` — testy serwisu.

**Dokumenty:** `PROJECT_PROGRESS.md` i `SESSION_HANDOFF.md` — aktualizacje tego checkpointu. Nie zakładać, że powyższy wykaz zastępuje rzeczywiste `git status`.

## 4. Architektura i niezmienniki bezpieczeństwa

- **Sprawdzony przepływ:** `Persisted Approval → ExecutionClaim → RemediationExecution(EXECUTING) → Fresh ApprovalExecutionGuard → reserve_verified_once() → RemediationDispatch`. Serwis sam wyznacza execution z request ID; klient nie podaje `execution_id` ani `VerifiedExecutionScope`.
- **Zaufana tożsamość zasobu:** Guard uruchamia świeży Preflight; `VerifiedExecutionContext(scope, target)` zawiera zakres i `ResolvedTarget` z tego samego przebiegu. Fingerprint obejmuje `resource_id`. Kontekst nie jest tokenem uprawniającym do MCP.
- **Transakcyjna kontrola:** `reserve_verified_once()` blokuje execution (`FOR UPDATE`), wymaga `EXECUTING`, sprawdza execution → claim → persisted Approval Request/Decision, `APPROVED` i okno decyzji, zgodność request/plan/step/fingerprint/policy oraz brak poprzedniej rezerwacji. `UNIQUE(execution_id)` pozostaje ostateczną ochroną; PostgreSQL nadaje czas rezerwacji. Błędy i odmowy nie są automatycznie ponawiane.
- **Wyścigi zweryfikowane:** verified reserve/verified reserve i verified reserve/outcome — co najwyżej jedna rezerwacja, odmowa po zmianie statusu.
- **Granica niezamknięta:** starsze `reserve_once(execution_id)` nie sprawdza zatwierdzonego zakresu i nadal istnieje. Przed zbudowaniem MCP Executor trzeba wyeliminować lub odizolować to obejście. Sam `ReservedVerifiedDispatch`, `EXECUTING` ani istniejący rekord dispatchu nie dają prawa do wywołania lub retry MCP.
- **Brak exactly-once efektu zewnętrznego:** commit rezerwacji przed możliwym wywołaniem nie dowodzi, czy pakiet dotarł do MCP. Po awarii, timeoucie lub utracie odpowiedzi **nie wznawiać automatycznie**. Potrzebne provider-side preconditions, idempotency/reconciliation i obsługa TOCTOU zasobu.
- **Auth/RBAC:** brak produkcyjnego uwierzytelniania i RBAC; nie dodawać domyślnego `allow-all`. Nie ujawniać portów persystencji dowolnym klientom ani nodom LangGraph jako uprzywilejowanych narzędzi.

## 5. Co zrobić dalej

1. Na lokalnych plikach: `git status --short`, `git diff --stat`, `git diff --check`. `??` nie są widoczne w zwykłym `git diff --stat`.
2. Po analizie wyłącznie uzgodnionych plików: `git add <konkretne ścieżki>`, `git diff --cached --check`, `git diff --cached --stat`, `git status --short`; potem commit, push i `git status -sb`.
3. Dopiero po zamknięciu Git zaprojektować **Secure MCP Execution Boundary**. Zacząć od analizy sposobu usunięcia/izolacji `reserve_once()` oraz tego, gdzie rzeczywisty wywołujący MCP sprawdza uprawnienie do pojedynczego dispatchu. Najpierw kontrakty i testy, bez przedwczesnego klienta MCP.
4. Przed zmianą istniejącego pliku obejrzeć **cały aktualny plik**. Małe iteracje i maksymalnie **8 plików testowych w partii**. `PROJECT_PROGRESS.md` aktualizować wyłącznie przy ważnych kamieniach milowych; `SESSION_HANDOFF.md` odświeżać przy większych zmianach i przed zmianą rozmowy.

**Powtarzalne kontrole:**

```bash
uv run ruff check src/ tests/ migrations/versions/
uv run ruff format --check src/ tests/ migrations/versions/
uv run mypy src/ai_incident_commander/
RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 uv run --env-file .env pytest -q
```
