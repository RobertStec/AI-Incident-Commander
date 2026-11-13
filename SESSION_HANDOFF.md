# AI Incident Commander — Session Handoff

> **Checkpoint:** 2026-11-13, po pełnej regresji **Trusted Crash Recovery** (`1.7.8.11.41.5`).
> **Cel:** płynne wznowienie pracy; `PROJECT_BRIEF.md` określa wizję, `PROJECT_PROGRESS.md` kamienie milowe.
> **Pierwszeństwo:** aktualny kod i wykonane polecenia > niniejszy checkpoint. Nie zakładać stanu repozytorium bez sprawdzenia Git.

## 1. Punkt wznowienia — co zrobić teraz

- **Kamień milowy zweryfikowany technicznie:** `1.7.8.11.41.5` — Trusted Crash Recovery dla *claimu zatwierdzonego w PostgreSQL, ale bez rozpoczętego wykonania*.
- **Ostatnia wykonana czynność:** pełna regresja lokalna `RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 uv run --env-file .env pytest -q` → **1186 passed w 24,62 s**. Ruff lint: PASS; Ruff format: **90 plików**; Mypy: **45 plików**, PASS.
- **Bieżący krok:** dokumentacja przygotowana do aktualizacji w repozytorium, ale **stan Git, commit i push bieżących zmian nie są jeszcze potwierdzone**. Najpierw sprawdzić zakres zmian (poniżej), następnie staging, commit i push.
- **Kolejny kierunek po commicie:** zaprojektować bezpieczną granicę MCP Executor (związanie z tożsamością zasobu, kontrola preconditions, niepewne efekty i reconciliation), iteracyjnie, bez automatycznego retry.

## 2. Git i potwierdzone testy

- **Ostatni potwierdzony commit/push:** `63d1ca8` — `feat: orchestrate approved remediation execution start`, gałąź `main` zsynchronizowana z `origin/main` bezpośrednio po commicie. Wcześniejszy kamień milowy Execution Lifecycle: `7b3086d` (również push).
- **Uwaga:** od commita `63d1ca8` przygotowano kolejne zmiany read-only claim lookup i Trusted Crash Recovery; **nie należy zakładać, że zostały zapisane w Git**. Widoczny wcześniej `git status` zawierał `SESSION_HANDOFF.md` jako `??`; nowa dokumentacja będzie wymagała kontroli.
- **Ostatnie potwierdzone wyniki wybranych testów:** recovery service + Guard + PostgreSQL: **20 passed** (`test_approval_execution_guard_integration.py`); repozytorium recovery ze współbieżnością: **12 passed** (`test_postgres_remediation_execution_recovery_integration.py`); jednostkowy Recovery Service: **14 passed**; polityka czasu: **16 passed**; port recovery: **7 passed**; claim lookup PostgreSQL: **18 passed**. Pełna regresja **1186 passed** obejmuje te zestawy.
- **Baza:** lokalny PostgreSQL uruchamiany z `.env`; rewizje Alembic `f4d2a6b8c901` (Claims) i `a31e5d79c204` (Execution Lifecycle). **Nie wprowadzono migracji na potrzeby recovery.**

## 3. Zmiany po `63d1ca8` — sprawdzić w rzeczywistym `git status`

### Istniejące pliki rozszerzone (według przeprowadzonych etapów)

- `src/ai_incident_commander/application/execution_claim_repository.py` — read-only `get_by_request_id()`.
- `src/ai_incident_commander/infrastructure/postgres_execution_claim_repository.py` — odczyt claimu bez osłabienia `claim_once()`.
- `src/ai_incident_commander/application/remediation_execution_repository.py` — osobny port recovery i jawne odmowy; standardowy port zachowany.
- `src/ai_incident_commander/infrastructure/postgres_remediation_execution_repository.py` — atomowy `start_recovered_once()`, standardowe `start_once()` pozostawione funkcjonalnie bez zmian.
- `tests/integration/test_postgres_execution_claim_repository_integration.py` — scenariusze odczytu claimu.
- `tests/integration/test_approval_execution_guard_integration.py` — pełny przepływ Trusted Recovery Service z rzeczywistym PostgreSQL.

### Nowe pliki (według przeprowadzonych etapów)

- `src/ai_incident_commander/domain/execution_claim_recovery_policy.py` — `ExecutionClaimRecoveryWindowPolicy(max_claim_age: timedelta)`, jawna konfiguracja bez domyślnego TTL.
- `src/ai_incident_commander/application/remediation_execution_recovery_service.py` — odczyt claimu → świeży Guard → recovery repository.
- `tests/unit/test_execution_claim_recovery_policy.py`.
- `tests/unit/test_remediation_execution_recovery_repository.py`.
- `tests/unit/test_remediation_execution_recovery_service.py`.
- `tests/integration/test_postgres_remediation_execution_recovery_integration.py` — w tym wyścigi recovery/recovery i recovery/standard start.
- `SESSION_HANDOFF.md` — checkpoint; `PROJECT_PROGRESS.md` — aktualizacja kamienia milowego. Obecny stan obu dokumentów na dysku użytkownika trzeba potwierdzić po ich podmianie.

## 4. Architektura i niezmienniki bezpieczeństwa

- **Standardowy start:** `ApprovalExecutionGuard` → `ExecutionClaimService.claim_for_step()` → `claim_once()` → `RemediationExecutionStartService.start_for_step()` / `start_once()`. Claim i EXECUTING to **dwie osobne zatwierdzone transakcje**. Identyczny retry claimu zawsze odrzucany.
- **Trusted Crash Recovery:** `RemediationExecutionRecoveryService.recover_for_step(request_id, step)` odczytuje istniejący claim przez `get_by_request_id()`, potem *ponownie* wywołuje `ApprovalExecutionGuard.verify_scope_for_step()`, a następnie `start_recovered_once(claim_id, verified_scope, recovery_policy)`.
- **Recovery repository:** w pojedynczej transakcji blokuje claim (`FOR UPDATE`), weryfikuje utrwalony Approval/Scope, sprawdza okno `0 <= database_now - claimed_at < max_claim_age` na zegarze PostgreSQL w momencie zapisu i dopuszcza **co najwyżej jeden** nowy rekord EXECUTING. Ochrona współbieżności obejmuje wyścig ze standardowym startem.
- **Odczyt claimu ani `VerifiedExecutionScope` od niezaufanego klienta nie są uprawnieniem.** Tylko zaufany serwis wywołuje Guard; repozytorium niezależnie sprawdza warunki możliwe do potwierdzenia w bazie. Samo PostgreSQL nie dowodzi świeżości zewnętrznego Preflight.
- **Granice:** istniejące `EXECUTING`, `UNKNOWN`, `SUCCEEDED`, `FAILED` nie dopuszcza nowego startu dla tego claimu. `UNKNOWN` wymaga reconciliation, a `FAILED` nie dowodzi braku skutku ubocznego. Nie ma jeszcze MCP Executor ani gwarancji exactly-once zewnętrznych efektów; TOCTOU zasobu zewnętrznego nadal pozostaje otwarte.
- **Auth:** brak produkcyjnego uwierzytelniania/RBAC; nie dodawać domyślnego `allow-all`. Nie rozszerzać Guard o prawo do działania.

## 5. Kolejność dalszych kroków

1. W repozytorium podmienić `PROJECT_PROGRESS.md` i `SESSION_HANDOFF.md` na nowe wersje z checkpointu.
2. Uruchomić `git status --short`, `git diff --stat`, `git diff --check`. Nie oceniać nowych plików na podstawie samego `git diff --stat` — są `??` do `git add`.
3. Po przeglądzie dodać **tylko uzgodnione pliki**, sprawdzić `git diff --cached --check`, `git diff --cached --stat` oraz `git status --short`. Potem commit/push i kontrola `git status -sb`.
4. Następny etap architektoniczny: określić kontrakt bezpiecznego uruchamiania operacji MCP, idempotency i reconciliation; przed zmianą każdego istniejącego pliku przeanalizować jego **całą aktualną wersję**.

## 6. Sposób współpracy

- Odpowiedzi po polsku, konkretnie i technicznie; małe iteracje. Maksymalnie **8 plików testowych** w partii. Po zmianie uruchamiać odpowiednie testy, dopiero potem przechodzić dalej.
- `PROJECT_PROGRESS.md` aktualizować **wyłącznie przy ważnych kamieniach milowych**; `SESSION_HANDOFF.md` jako osobny punkt przekazania sesji. Asystent sam proponuje checkpoint po większych zmianach, bez deklarowania znajomości granicy okna kontekstowego.
- Kontrola jakości: `uv run ruff check src/ tests/ migrations/versions/`; `uv run ruff format --check src/ tests/ migrations/versions/`; `uv run mypy src/ai_incident_commander/`.
- Pełna regresja: `RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 uv run --env-file .env pytest -q`.
