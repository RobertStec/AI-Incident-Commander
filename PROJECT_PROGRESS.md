# AI Incident Commander — Project Progress

> **Cel:** zwięzła pamięć techniczna projektu, umożliwiająca wznowienie pracy w nowej konwersacji.
> **Dokument nadrzędny:** `PROJECT_BRIEF.md` — wizja, wymagania i roadmapa.
> **Zasada aktualizacji:** wpisy tylko przy **istotnych kamieniach milowych architektury**, zmianach kluczowych kontraktów lub decyzjach bezpieczeństwa. Nie dokumentujemy osobno każdego testu, drobnej poprawki, etapu pośredniego ani commita.
> **Źródło szczegółowej historii zmian:** Git i testy w repozytorium. Nie oznaczamy planów jako ukończonej implementacji.

## 1. Aktualny stan projektu

- **Obszar:** Human-in-the-Loop — zabezpieczenie wykonania operacji remediation.
- **Ostatni kamień milowy:** **Atomic Execution Claim** (`1.7.8.11.38`) — zaimplementowany i zweryfikowany na PostgreSQL; **commit i push jeszcze niewykonane**.
- **Najnowsza pełna regresja:** **1020 passed, 0 failed, 0 skipped** (2026-11-12). Ruff lint/format: PASSED; Mypy: 37 plików, bez błędów.
- **Migracja bazy:** `f4d2a6b8c901` zastosowana w lokalnej bazie PostgreSQL; test zgodności schematu przeszedł.
- **Ostatni potwierdzony push przed zmianami Atomic Execution Claim:** `b4b9986` na `origin/main` (ApprovalExecutionGuard). Aktualnego stanu Git dla oczekujących zmian nie sprawdzono jeszcze po ostatniej regresji.
- **Bezpośredni następny krok:** sprawdzić Git, zatwierdzić i wypchnąć zmiany Atomic Execution Claim; następnie zaprojektować serwis aplikacyjny łączący `ApprovalExecutionGuard` z `ExecutionClaimRepository.claim_once()`.

## 2. Kluczowe decyzje i granice bezpieczeństwa

- **Podział odpowiedzialności:** Preflight i fingerprint weryfikują operację; Approval Request/Decision przechowują decyzję człowieka; `ApprovalExecutionGuard` sprawdza zgodność zatwierdzenia z aktualnym krokiem; `ExecutionClaimRepository` rezerwuje wykonanie atomowo. Nie łączymy tych odpowiedzialności w jeden komponent.
- **Zaufane zatwierdzenie:** decyzję odczytujemy z PostgreSQL (`get_decision()`), a nie z danych dostarczonych przez klienta, LangGraph lub MCP. Wymagana jest utrwalona decyzja `APPROVED`.
- **Approval persistence:** `record_decision_once()` używa transakcji i `SELECT ... FOR UPDATE`; weryfikuje aktywność żądania według zegara PostgreSQL po uzyskaniu blokady. `UNIQUE(request_id)` uniemożliwia drugą decyzję; nieoczekiwane błędy SQL nie są maskowane.
- **Powiązanie operacji:** Action Fingerprint obejmuje krok, parametry, zweryfikowany cel i wersję polityki. Guard ponawia zaufany Preflight i porównuje aktualny zakres z utrwalonym Approval Request.
- **Approval window ≠ execution window:** `requested_at`/`expires_at` określają okno podjęcia decyzji; nie definiują odrębnego terminu wykonania. Polityka ważności wykonania pozostaje do zaprojektowania.
- **Atomic Execution Claim:** identyfikator kroku `(plan_id, step_id)` jest unikalny niezależnie od `request_id`; dodatkowe `UNIQUE(request_id)` zapobiega wielokrotnemu użyciu jednego zatwierdzenia. Ponowienie `claim_once()` **odmawia** wydania kolejnego claimu, nawet dla identycznych argumentów.
- **Autoryzacja w transakcji:** adapter claimów ponownie sprawdza utrwalone `APPROVED`, zgodność identyfikatorów, fingerprintu, polityki i czasu decyzji; dopiero następnie zapisuje claim. `claimed_at` pochodzi z `clock_timestamp()` PostgreSQL.
- **Granica gwarancji:** claim nie jest wykonaniem MCP i nie zapewnia *exactly-once execution* w systemie zewnętrznym. Nadal potrzebne są: bezpieczne powiązanie Guard → Claim → Executor, idempotency/uzgadnianie stanu po stronie narzędzia, obsługa niepewnego rezultatu oraz zmian celu pomiędzy kontrolą a wykonaniem.
- **Composition Root:** zależności wstrzykujemy jawnie; brak domyślnego autoryzatora `allow-all`. Życie `AsyncEngine` jest zarządzane przez async context manager; warstwa aplikacji nie zależy od FastAPI ani LangGraph.

## 3. Kamienie milowe

### 2026-11-11 — Organizacja testów i trwała persystencja zatwierdzeń

- Rozdzielono testy na `tests/unit/` i `tests/integration/` (commit `5707724`).
- Wdrożono `PostgresApprovalRepository`, transakcyjny `record_decision_once()`, ochronę współbieżności i kontrolę ważności według PostgreSQL. Przetestowano m.in. wygaśnięcie podczas oczekiwania na blokadę, konflikt operatorów i rollback (commit `097db9c`).
- Rezultat: trwała, atomowa rejestracja maksymalnie jednej decyzji dla żądania.

### 2026-11-11 — Composition Root i trwały Approval Application Service

- Dodano niezależny od frameworka Composition Root z jawnym wstrzykiwaniem autoryzatora i zarządzaniem cyklem życia `AsyncEngine` (`9f6963d`).
- Zweryfikowano integracyjnie zapis decyzji przez serwis aplikacyjny z rzeczywistym PostgreSQL, odmowę dla nieuprawnionego operatora oraz pojedynczą decyzję między cyklami życia (`64e4e58`).

### 2026-11-12 — Pełny przepływ Approval Request → Decision

- Dodano `ApprovalRequestCreationService`: zaufany Preflight → fingerprint → żądanie. `approval_workflow_lifespan()` współdzieli repozytorium, zegar i silnik pomiędzy serwisem żądań i decyzji (`3a69dc9`).
- Przepływ od `RemediationStep` do utrwalonej decyzji został zweryfikowany integracyjnie; zachowano wcześniejszy kontrakt `approval_service_lifespan()`.

### 2026-11-12 — Trusted Decision Read

- Dodano `ApprovalRepository.get_decision(request_id)` i implementację PostgreSQL; odczyt odtwarza `RemediationApprovalDecision` i normalizuje czas do UTC.
- Brak decyzji zwraca `None`; `APPROVED` i `REJECTED` pozostają rozróżnione. Bez migracji schematu.
- Testy jednostkowe i integracyjne zakończone pomyślnie; commit `526b457`.

### 2026-11-12 — ApprovalExecutionGuard

- Oddzielny komponent sprawdza zapisane zatwierdzenie, tożsamość kroku, aktualny Preflight, wersję polityki i fingerprint; nie rezerwuje ani nie wykonuje operacji.
- Zweryfikowano odmowę dla braku/odrzucenia decyzji i niezgodnego zakresu, również z rzeczywistym PostgreSQL.
- **13 testów Guard** (9 jednostkowych, 4 integracyjne); commit `b4b9986` wypchnięty na `origin/main`.

### 2026-11-12 — Atomic Execution Claim

- Dodano niezmienny model `ExecutionClaim`, port `ExecutionClaimRepository.claim_once()` i `PostgresExecutionClaimRepository`.
- Dodano tabelę `remediation_execution_claims`, `UNIQUE(plan_id, step_id)` i `UNIQUE(request_id)` oraz migrację Alembic `f4d2a6b8c901`; migracja zastosowana lokalnie i sprawdzona testami schematu.
- Adapter w jednej transakcji weryfikuje utrwaloną decyzję `APPROVED`, zgodność zakresu i atomowo zapisuje rezerwację. `claimed_at` nadaje PostgreSQL.
- Testy integracyjne wykazały **jednego zwycięzcę** przy równoczesnym claimie z tym samym `request_id` oraz z różnymi zatwierdzeniami dla tego samego kroku.
- **Pełna regresja: 1020 passed; Ruff i Mypy: PASSED.**
- **Status: zweryfikowany technicznie; jeszcze niezatwierdzony i niewypchnięty w Git.**

## 4. Co pozostało do zaprojektowania

- **Najbliżej:** serwis aplikacyjny koordynujący `ApprovalExecutionGuard` i atomowe `claim_once()`; testy integracji oraz zachowania przy błędach i retry.
- **Przed uruchamianiem MCP:** lifecycle wykonania, trwały status, kontrola niepewnego wyniku, idempotency downstream, zachowanie przy restartach LangGraph i zmianie tożsamości zasobu.
- **Dalsze prace:** rzeczywiste uwierzytelnianie i produkcyjny RBAC, integracja HITL/LangGraph, adaptery MCP i pozostałe elementy roadmapy z `PROJECT_BRIEF.md`.

## 5. Wznowienie pracy i zasady współpracy

- Przed każdą zmianą istniejącego pliku analizujemy **cały aktualny plik**; nie rekonstruujemy kodu z tego dokumentu.
- Pracujemy iteracyjnie: mała zmiana → testy odpowiednie dla warstwy → analiza wyniku → dalszy krok. Maksymalnie 8 plików testowych na jedną partię.
- Testy integracyjne wymagają lokalnej, izolowanej bazy PostgreSQL. Używane polecenie pełnej regresji:

  ```bash
  RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 \
  uv run --env-file .env pytest -q
  ```

- Kontrole jakości: `uv run ruff check src/ tests/ migrations/versions/`, `uv run ruff format --check src/ tests/ migrations/versions/`, `uv run mypy src/ai_incident_commander/`.
- `PROJECT_PROGRESS.md` aktualizujemy **wyłącznie przy znaczącym kamieniu milowym**; Git przechowuje zmiany szczegółowe. Każdy wpis rozróżnia: *zaplanowane*, *zaimplementowane*, *zweryfikowane*, *commit/push*.
- W nowej rozmowie udostępnić `PROJECT_PROGRESS.md` i `PROJECT_BRIEF.md`; przed kolejną implementacją potwierdzić bieżący stan Git oraz kodu.
