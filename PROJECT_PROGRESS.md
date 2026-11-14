# AI Incident Commander — Project Progress

> **Cel:** zwięzła pamięć techniczna projektu, umożliwiająca wznowienie pracy w nowej konwersacji.
> **Dokument nadrzędny:** `PROJECT_BRIEF.md` — wizja, wymagania i roadmapa.
> **Zasada aktualizacji:** wpisy tylko przy **istotnych kamieniach milowych architektury**, zmianach kluczowych kontraktów lub decyzjach bezpieczeństwa. Nie dokumentujemy osobno każdego testu, drobnej poprawki, etapu pośredniego ani commita.
> **Źródło szczegółowej historii zmian:** Git i testy w repozytorium. Nie oznaczamy planów jako ukończonej implementacji.

## 1. Aktualny stan projektu

- **Obszar:** Human-in-the-Loop — kontrola zatwierdzeń, rezerwacji i trwałego stanu wykonania remediation.
- **Ostatni kamień milowy:** **Verified Dispatch Authorization & Trusted Dispatch Service** (`1.7.8.11.42.6`) — świeży Guard, zaufane powiązanie `request_id → claim → execution`, transakcyjne `reserve_verified_once()` w PostgreSQL i trwała rezerwacja dispatchu. Implementacja i testy zweryfikowane; **commit/push tego kamienia milowego jeszcze niepotwierdzone**.
- **Najnowsza pełna regresja:** **1276 passed** (2026-11-14, lokalny PostgreSQL z testami opt-in; 28,77 s). Ruff lint: PASSED, format: **102 pliki**; Mypy: PASSED, **50 plików źródłowych**.
- **Migracje PostgreSQL:** `f4d2a6b8c901` (Execution Claims), `a31e5d79c204` (Execution Lifecycle), `c4f8a2d7e951` (Dispatch Reservations) — zastosowane lokalnie; ostatnia rewizja potwierdzona jako `(head)`, test schematu zaliczony.
- **Git:** ostatni potwierdzony commit/push `4aaa1ff` (`Durable MCP Dispatch Reservation`) na `origin/main`; po nim working tree był czysty. **Bieżące zmiany Trusted Dispatch Service nie mają jeszcze potwierdzonego commita/pushu; aktualny Git wymaga sprawdzenia**.
- **Bezpośredni następny krok:** podmienić oba dokumenty, sprawdzić `git status --short`, `git diff --stat` i `git diff --check`; następnie staging tylko uzgodnionych plików, kontrola staged diff, commit i push. Kolejny obszar: Secure MCP Execution Boundary (bez faktycznego dispatchu do czasu zamknięcia luk autoryzacji).

## 2. Kluczowe decyzje i granice bezpieczeństwa

- **Oddzielne odpowiedzialności:** zaufany Preflight i Action Fingerprint identyfikują operację; Approval Request/Decision rejestrują decyzję człowieka; `ApprovalExecutionGuard` weryfikuje zgodność; `ExecutionClaimRepository` atomowo rezerwuje krok; `RemediationExecutionRepository` utrwala przebieg pojedynczej próby.
- **Zaufane zatwierdzenie:** decyzja `APPROVED` pochodzi z PostgreSQL (`get_decision()`), nie z klienta, LangGraph ani MCP. `record_decision_once()` chronią transakcja, `SELECT ... FOR UPDATE`, zegar bazy i `UNIQUE(request_id)`.
- **Powiązanie zakresu:** fingerprint obejmuje krok, parametry, zweryfikowany cel i wersję polityki. Guard ponawia zaufany Preflight. `ExecutionClaimService` przekazuje `VerifiedExecutionScope` bez powtórnego Preflight; repozytorium ponownie weryfikuje zatwierdzenie i zakres w transakcji.
- **Approval window ≠ recovery window:** `requested_at`/`expires_at` ograniczają moment decyzji operatora, nie termin wykorzystania claimu. Osobna `ExecutionClaimRecoveryWindowPolicy(max_claim_age)` ogranicza **odzyskiwanie** po `claimed_at`; nie ustanawia ogólnej gwarancji wykonania ani prawa do MCP.
- **Atomic Execution Claim:** `UNIQUE(plan_id, step_id)` oraz `UNIQUE(request_id)` zapobiegają ponownej rezerwacji. `claimed_at` pochodzi z PostgreSQL. Identyczny retry `claim_once()` kończy się odmową.
- **Execution Claim ≠ Execution Lifecycle:** claim identyfikuje rezerwację; osobny `RemediationExecution` identyfikuje próbę i jej stan: `EXECUTING → SUCCEEDED / FAILED / UNKNOWN`. Jedna próba na `claim_id` (`UNIQUE(claim_id)`).
- **Trwałość i współbieżność:** `start_once()` zatwierdza `EXECUTING` przed planowanym wywołaniem MCP i odmawia ponownego startu; `record_outcome_once()` zapisuje pierwszy wynik warunkowym `UPDATE` i nie pozwala go nadpisać; `get_by_claim_id()` wyłącznie odczytuje. Czas pochodzi z `clock_timestamp()` PostgreSQL. Obie operacje zapisu przeszły testy konkurujących workerów.
- **Zaufane recovery:** `get_by_request_id()` jedynie odczytuje claim; `RemediationExecutionRecoveryService` ponownie uruchamia Guard; odrębne `start_recovered_once()` blokuje claim, porównuje utrwalone zatwierdzenie i zakres, sprawdza okno wieku claimu zegarem PostgreSQL i zapisuje najwyżej jedno `EXECUTING`. Współbieżność recovery/recovery i recovery/standard start przetestowana.
- **Powiązanie z zasobem:** `ApprovalExecutionGuard.verify_execution_context_for_step()` zwraca `VerifiedExecutionContext(scope, target)` z tego samego zaufanego Preflight; starsze API Guard zachowano. `ResolvedTarget.resource_id` uczestniczy w Action Fingerprint. Ten kontekst nie stanowi samodzielnego uprawnienia do MCP.
- **Durable dispatch reservation:** osobny `RemediationDispatch` i `PostgresRemediationDispatchRepository.reserve_once()` rezerwują co najwyżej jedną próbę dispatchu na wykonanie `EXECUTING`. Transakcja blokuje rekord execution (`FOR UPDATE`), sprawdza status, odmawia duplikatu, nadaje czas z PostgreSQL; `UNIQUE(execution_id)` zabezpiecza bazę. `get_by_execution_id()` tylko odczytuje. Przetestowano wyścigi rezerwacja/rezerwacja i rezerwacja/zapis wyniku.
- **Verified dispatch authorization:** `reserve_verified_once(execution_id, verified_scope)` w jednej transakcji sprawdza execution → claim → utrwalone Approval Request/Decision, status `EXECUTING`, zgodność `request_id`, planu, kroku, fingerprintu i polityki, poprawne okno zatwierdzenia oraz brak wcześniejszej rezerwacji. Przetestowano wyścigi verified reserve/verified reserve i verified reserve/outcome.
- **Trusted Dispatch Service:** `RemediationTrustedDispatchService.reserve_for_step(request_id, step)` sam odczytuje claim i execution, uzyskuje świeży `VerifiedExecutionContext` z Guard i wywołuje `reserve_verified_once()`. Nie przyjmuje `execution_id` ani scope od klienta, nie wywołuje MCP i nie ponawia odmów. Zwracany `ReservedVerifiedDispatch` nie jest tokenem do wykonania.
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
- **Weryfikacja kamienia milowego:** pełna regresja **1109 passed**; Ruff i Mypy: PASSED. **Status Git:** commit/push `7b3086d` na `origin/main`.

### 2026-11-13 — Standardowa orkiestracja i Trusted Crash Recovery

- `RemediationExecutionStartService` połączył Guard → atomowy Claim → trwały `EXECUTING` bez wywołań MCP i bez automatycznego retry. **Commit/push:** `63d1ca8`.
- Dodano odczyt `ExecutionClaimRepository.get_by_request_id()` oraz osobną, konfigurowalną `ExecutionClaimRecoveryWindowPolicy` z granicą `0 <= wiek < max_claim_age`.
- `RemediationExecutionRecoveryService` przy istniejącym claimie uruchamia świeży Guard; osobny `RemediationExecutionRecoveryRepository.start_recovered_once()` atomowo sprawdza utrwalone zatwierdzenie, zgodność zakresu, czas PostgreSQL i brak wcześniejszej próby, po czym zapisuje `EXECUTING`.
- Testy jednostkowe, integracyjne i kontrolowana współbieżność **recovery vs recovery** oraz **recovery vs standard start** zaliczone. **Pełna regresja: 1186 passed; Ruff/Mypy: PASSED**. **Status Git recovery:** commit/push `1ebfdda` na `origin/main`.
- **Granica:** obejmuje wyłącznie claim bez rozpoczętej próby; nie wznawia `EXECUTING`/`UNKNOWN` i nie rozwiązuje TOCTOU w zewnętrznym systemie MCP.

### 2026-11-14 — VerifiedExecutionContext i Durable MCP Dispatch Reservation

- `ApprovalExecutionGuard` udostępnia `verify_execution_context_for_step()` zwracające `VerifiedExecutionContext(scope, target)` z jednego Preflight; istniejące metody `verify_scope_for_step()` i `validate_for_step()` zachowano.
- Dodano `RemediationDispatch`, port `RemediationDispatchRepository` (`reserve_once()`, `get_by_execution_id()`) oraz adapter `PostgresRemediationDispatchRepository`. Rezerwacja jest zatwierdzana przed potencjalną próbą MCP; identyczny retry kończy się odmową.
- Nowa tabela `remediation_dispatches`: PK `dispatch_id`, FK `execution_id` z `ON DELETE RESTRICT`, `UNIQUE(execution_id)`, `reserved_at` z zegara PostgreSQL. Migracja `c4f8a2d7e951` zastosowana, test schematu zaliczony.
- Testy PostgreSQL obejmują konkurencję **reserve vs reserve** i **reserve vs outcome**. **Pełna regresja przy zamknięciu etapu: 1225 passed; Ruff/Mypy: PASSED**. **Status Git:** commit/push `4aaa1ff` na `origin/main`.
- **Granica:** rezerwacja jest trwałym faktem, nie zdarzeniem wysłania ani uprawnieniem do wykonania MCP. Na tym etapie nie istniały jeszcze Trusted Dispatch Service, MCP Executor ani reconciliation.

### 2026-11-14 — Verified Dispatch Authorization & Trusted Dispatch Service

- Dodano osobny port `RemediationVerifiedDispatchRepository.reserve_verified_once(execution_id, verified_scope)` i jawne odmowy dla braku/niespójności zatwierdzenia i zakresu; stary kontrakt rezerwacji zachowano tymczasowo.
- `PostgresRemediationDispatchRepository.reserve_verified_once()` transakcyjnie blokuje wykonanie, weryfikuje powiązany claim i utrwalone `APPROVED` w poprawnym oknie czasowym, porównuje cały zatwierdzony zakres i zapisuje jedną rezerwację. Bez nowej migracji.
- `RemediationTrustedDispatchService` wyszukuje trwały claim i execution z `request_id`, następnie wykonuje świeży Guard (jeden Preflight) i wywołuje zweryfikowaną rezerwację. Zwraca `ReservedVerifiedDispatch` (wynik, **nie** capability), nigdy nie wywołuje MCP.
- Zweryfikowano odmowy dla podmienionej tożsamości zasobu, niespójnych danych execution/claim/approval, duplikatów i stanów końcowych oraz rzeczywistą współbieżność verified reserve/verified reserve i verified reserve/outcome. **Pełna regresja: 1276 passed; Ruff/Mypy: PASSED.** **Status Git:** bieżący commit/push jeszcze niepotwierdzone.
- **Granica:** starsze `reserve_once()` nadal istnieje jako alternatywna, niezweryfikowana ścieżka rezerwacji; przed MCP musi zostać wyeliminowana lub odizolowana. Brak wykonawcy MCP, ochrony provider-side TOCTOU i reconciliation.

## 4. Co pozostało do zaprojektowania

- **Najbliżej:** po kontroli Git zatwierdzić i wypchnąć **Verified Dispatch Authorization & Trusted Dispatch Service**. Następnie zaprojektować **Secure MCP Execution Boundary**: usunąć/odizolować obejście przez `reserve_once()`, określić nieodtwarzalną granicę wywołania narzędzia i zasady dostępu do adapterów.
- **Przed uruchamianiem MCP:** kontrola tego, kto może faktycznie wykonać wywołanie po rezerwacji (bez bearer tokenów i replays), provider-side warunki na konkretnym zasobie, downstream idempotency/reconciliation, polityka niepewnych rezultatów, wznowienia LangGraph i ograniczenie TOCTOU pomiędzy Preflight a efektem zewnętrznym. Sam `ReservedVerifiedDispatch` nie rozwiązuje tych zagadnień.
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
- W nowej rozmowie udostępnić `PROJECT_BRIEF.md`, `PROJECT_PROGRESS.md` i najnowszy `SESSION_HANDOFF.md`; przed kolejną implementacją potwierdzić aktualny Git i kod.
