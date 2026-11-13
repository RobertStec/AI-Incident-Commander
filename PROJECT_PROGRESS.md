# AI Incident Commander — Project Progress

> **Cel:** zwięzła pamięć techniczna projektu, umożliwiająca wznowienie pracy w nowej konwersacji.
> **Dokument nadrzędny:** `PROJECT_BRIEF.md` — wizja, wymagania i roadmapa.
> **Zasada aktualizacji:** wpisy tylko przy **istotnych kamieniach milowych architektury**, zmianach kluczowych kontraktów lub decyzjach bezpieczeństwa. Nie dokumentujemy osobno każdego testu, drobnej poprawki, etapu pośredniego ani commita.
> **Źródło szczegółowej historii zmian:** Git i testy w repozytorium. Nie oznaczamy planów jako ukończonej implementacji.

## 1. Aktualny stan projektu

- **Obszar:** Human-in-the-Loop — kontrola zatwierdzeń, rezerwacji i trwałego stanu wykonania remediation.
- **Ostatni kamień milowy:** **Durable Remediation Execution Lifecycle** (`1.7.8.11.40`) — model, port, schemat i adapter PostgreSQL zaimplementowane; testy jednostkowe, integracyjne i współbieżności zaliczone; **commit/push tego kamienia milowego oczekują**.
- **Najnowsza pełna regresja:** **1109 passed** (2026-11-13). Ruff lint/format: PASSED (82 pliki); Mypy: PASSED (42 pliki źródłowe).
- **Migracje PostgreSQL:** `f4d2a6b8c901` (Execution Claims) oraz `a31e5d79c204` (Execution Lifecycle) zastosowane lokalnie; testy zgodności schematów zaliczone.
- **Git:** ostatni potwierdzony push `2ebea2a` na `origin/main` (Guard → Atomic Claim). Ostatnia kontrola wykazała **9 nowych, nieśledzonych plików** Execution Lifecycle; nie obejmowała jeszcze tej aktualizacji dokumentu.
- **Bezpośredni następny krok:** dodać `PROJECT_PROGRESS.md` i 9 plików Execution Lifecycle do staging area, sprawdzić staged diff, wykonać commit/push. Następnie zaprojektować bezpieczną orkiestrację Claim → Execution Lifecycle, nadal bez wywołań MCP.

## 2. Kluczowe decyzje i granice bezpieczeństwa

- **Oddzielne odpowiedzialności:** zaufany Preflight i Action Fingerprint identyfikują operację; Approval Request/Decision rejestrują decyzję człowieka; `ApprovalExecutionGuard` weryfikuje zgodność; `ExecutionClaimRepository` atomowo rezerwuje krok; `RemediationExecutionRepository` utrwala przebieg pojedynczej próby.
- **Zaufane zatwierdzenie:** decyzja `APPROVED` pochodzi z PostgreSQL (`get_decision()`), nie z klienta, LangGraph ani MCP. `record_decision_once()` chronią transakcja, `SELECT ... FOR UPDATE`, zegar bazy i `UNIQUE(request_id)`.
- **Powiązanie zakresu:** fingerprint obejmuje krok, parametry, zweryfikowany cel i wersję polityki. Guard ponawia zaufany Preflight. `ExecutionClaimService` przekazuje `VerifiedExecutionScope` bez powtórnego Preflight; repozytorium ponownie weryfikuje zatwierdzenie i zakres w transakcji.
- **Approval window ≠ execution window:** `requested_at`/`expires_at` opisują okno decyzji, nie odrębny termin wykonania. Polityka ważności wykonania pozostaje do zaprojektowania.
- **Atomic Execution Claim:** `UNIQUE(plan_id, step_id)` oraz `UNIQUE(request_id)` zapobiegają ponownej rezerwacji. `claimed_at` pochodzi z PostgreSQL. Identyczny retry `claim_once()` kończy się odmową.
- **Execution Claim ≠ Execution Lifecycle:** claim identyfikuje rezerwację; osobny `RemediationExecution` identyfikuje próbę i jej stan: `EXECUTING → SUCCEEDED / FAILED / UNKNOWN`. Jedna próba na `claim_id` (`UNIQUE(claim_id)`).
- **Trwałość i współbieżność:** `start_once()` zatwierdza `EXECUTING` przed planowanym wywołaniem MCP i odmawia ponownego startu; `record_outcome_once()` zapisuje pierwszy wynik warunkowym `UPDATE` i nie pozwala go nadpisać; `get_by_claim_id()` wyłącznie odczytuje. Czas pochodzi z `clock_timestamp()` PostgreSQL. Obie operacje zapisu przeszły testy konkurujących workerów.
- **Niepewny efekt zewnętrzny:** `EXECUTING` po restarcie nie jest pozwoleniem na retry; `UNKNOWN` wymaga odrębnego reconciliation. `FAILED` nie jest automatycznym dowodem braku skutków ubocznych. **Brak gwarancji exactly-once execution po stronie MCP**; wykonawca MCP, idempotency downstream i uzgadnianie rezultatów nie są jeszcze zaimplementowane.
- **Composition Root i autoryzacja:** jawne zależności i lifecycle `AsyncEngine` bez uzależniania aplikacji od FastAPI/LangGraph. Brak produkcyjnego uwierzytelniania/RBAC i brak domyślnego autoryzatora `allow-all`.

## 3. Kamienie milowe

### 2026-11-11 — Organizacja testów i trwała persystencja zatwierdzeń

- Rozdzielono testy na `tests/unit/` i `tests/integration/`.
- `PostgresApprovalRepository`: atomowe `record_decision_once()`, ochrona współbieżności, sprawdzanie aktywności żądania według PostgreSQL, rollback i kontrola konfliktów.
- **Rezultat:** co najwyżej jedna trwała decyzja na Approval Request; zweryfikowane testami integracyjnymi.

### 2026-11-11 — Composition Root i Approval Application Service

- Dodano niezależny od frameworka Composition Root z jawnym wstrzykiwaniem autoryzatora oraz cyklem życia `AsyncEngine`.
- Zweryfikowano zapis decyzji z PostgreSQL, odmowę dla nieuprawnionego operatora i ochronę przed drugą decyzją między cyklami życia.

### 2026-11-12 — Approval Request → Decision i Trusted Decision Read

- `ApprovalRequestCreationService`: zaufany Preflight → fingerprint → żądanie; wspólny lifecycle serwisów tworzenia żądania i decyzji.
- `ApprovalRepository.get_decision()` zwraca utrwalone `APPROVED`/`REJECTED` lub `None`, z normalizacją czasu UTC. Przepływ sprawdzono integracyjnie.

### 2026-11-12 — ApprovalExecutionGuard

- Guard weryfikuje utrwalone zatwierdzenie, tożsamość kroku, aktualny Preflight, fingerprint i politykę; sam nie rezerwuje i nie wykonuje operacji.
- Przetestowano odmowy dla braku/odrzucenia decyzji oraz zmiany zakresu, także na PostgreSQL.

### 2026-11-12 — Atomic Execution Claim

- Dodano `ExecutionClaim`, port `claim_once()`, adapter PostgreSQL, tabelę `remediation_execution_claims` i migrację `f4d2a6b8c901`.
- `UNIQUE(plan_id, step_id)` i `UNIQUE(request_id)` oraz transakcyjna ponowna kontrola zatwierdzenia zapewniają jednokrotną rezerwację w testowanych warunkach współbieżności.
- **Status Git:** commit `3319a17` wypchnięty na `origin/main`.

### 2026-11-12 — VerifiedExecutionScope i ExecutionClaimService

- Guard zwraca niezmienny `VerifiedExecutionScope`, zachowując wcześniejsze API `validate_for_step()`.
- `ExecutionClaimService` łączy Guard z `claim_once()` bez ponownego uruchamiania Preflight; odmowy i błędy propaguje zamiast maskować.
- Pełen przepływ zatwierdzenie → Guard → Claim przetestowano z PostgreSQL. **Status Git:** commit `2ebea2a` wypchnięty na `origin/main`.

### 2026-11-13 — Durable Remediation Execution Lifecycle

- Dodano niezmienny `RemediationExecution` ze stanami `EXECUTING`, `SUCCEEDED`, `FAILED`, `UNKNOWN` oraz port `RemediationExecutionRepository`.
- Wdrożono tabelę `remediation_executions`, `UNIQUE(claim_id)`, klucz obcy do claimów, ograniczenia `CHECK` i migrację `a31e5d79c204`.
- `PostgresRemediationExecutionRepository`: `start_once()` (jeden trwały start), `record_outcome_once()` (jednorazowy atomowy wynik) i `get_by_claim_id()` (odczyt bez skutków ubocznych).
- Testy na rzeczywistym PostgreSQL objęły zapis/odczyt, wszystkie statusy i kontrolowane wyścigi współbieżnych workerów przy starcie oraz zapisie wyniku.
- **Weryfikacja:** pełna regresja **1109 passed**; Ruff i Mypy: PASSED. **Status Git:** 9 plików nowego komponentu nie zostało jeszcze zatwierdzonych i wypchniętych.

## 4. Co pozostało do zaprojektowania

- **Najbliżej:** po commicie/pushu przygotować serwis łączący atomowy Claim z trwałym `start_once()` oraz jasno określić granicę uprawnienia do pojedynczego wywołania narzędzia.
- **Przed MCP:** bezpieczne wywołanie, polityka błędów i niepewnego rezultatu, downstream idempotency/reconciliation, wznowienia LangGraph, kontrola zmian celu między weryfikacją a działaniem i osobna polityka czasu wykonania.
- **Dalsze prace:** produkcyjne uwierzytelnianie/RBAC, HITL/LangGraph, serwery i klient MCP, RAG, observability, CI/CD i deployment według `PROJECT_BRIEF.md`.

## 5. Wznowienie pracy i zasady współpracy

- Przed zmianą istniejącego pliku analizujemy **cały aktualny plik**; nie odtwarzamy jego zawartości na podstawie tego dokumentu.
- Pracujemy iteracyjnie: mała zmiana → właściwe testy → analiza wyniku → kolejny krok. Maksymalnie 8 plików testowych w jednej partii.
- Pełna regresja na lokalnym PostgreSQL:

  ```bash
  RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 \
  uv run --env-file .env pytest -q
  ```

- Kontrole jakości: `uv run ruff check src/ tests/ migrations/versions/`, `uv run ruff format --check src/ tests/ migrations/versions/`, `uv run mypy src/ai_incident_commander/`.
- `PROJECT_PROGRESS.md` aktualizujemy **tylko przy kamieniach milowych**; Git dokumentuje szczegóły. Rozróżniamy *zaplanowane*, *zaimplementowane*, *zweryfikowane* oraz *commit/push*.
- W nowej rozmowie udostępnić `PROJECT_PROGRESS.md` i `PROJECT_BRIEF.md`; przed kolejną implementacją potwierdzić aktualny Git i kod.
