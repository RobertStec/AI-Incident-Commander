# AI Incident Commander — Project Progress

> **Cel pliku:** krótka, aktualna pamięć techniczna projektu, którą można przenieść do nowej konwersacji.
> **Dokument nadrzędny:** `PROJECT_BRIEF.md` (wizja, wymagania i roadmapa).
> **Zasada:** zapisujemy tylko fakty potwierdzone w kodzie/testach, ważne decyzje oraz informacje potrzebne do wznowienia pracy. Nie traktujemy planów jako ukończonej implementacji.

## 1. Bieżący stan

- **Zakończony etap:** Status: 1.7.8.11.31 — zakończony technicznie, oczekuje na wersjonowanie w Git.

## 2. Ustalone decyzje architektoniczne

### Approval persistence — `record_decision_once()`

- Wykorzystujemy `AsyncEngine` i transakcję `async with engine.begin()`.
- W obrębie transakcji blokujemy rekord żądania przez `SELECT ... FOR UPDATE` (bez `NOWAIT` i `SKIP LOCKED`), aby serializować konkurujące zapisy do tego samego `request_id`.
- Kolejność rozstrzygnięć: brak żądania → istniejąca decyzja → nieaktywne okno czasowe → zapis.
- Aktywność oceniamy względem zegara bazy po pozyskaniu blokady, **nie** względem `decision.decided_at`.
- W zapisanym kodzie warunkowy `INSERT ... SELECT` używa `clock_timestamp()` i tej samej wartości do walidacji okna oraz kolumny `recorded_at`.
- Ograniczenie `uq_approval_decisions_request_id` (`UNIQUE(request_id)`) stanowi dodatkową ochronę integralności.
- Potwierdzone wyjątki kontraktu: `ApprovalRequestNotFoundError`, `ApprovalRequestNotActiveError`, `ApprovalAlreadyDecidedError`.
- Wymagane zachowanie nieoczekiwanych błędów SQL: nie maskować ich błędami domenowymi.

## 3. Pliki powiązane z bieżącym krokiem

- `src/ai_incident_commander/infrastructure/postgres_approval_repository.py` — adapter; istniejące `create_request()` i `get_request()` zachowane.
- `src/ai_incident_commander/application/approval_repository.py` — port i wyjątki.
- `src/ai_incident_commander/domain/remediation_approval.py` — modele żądań i decyzji.
- `src/ai_incident_commander/infrastructure/approval_tables.py` — tabela żądań i decyzji, w tym `recorded_at` oraz `UNIQUE(request_id)`.

**Ważne:** przy kolejnych zmianach w kodzie zawsze prosimy o *cały aktualny plik*, zamiast zakładać jego zawartość na podstawie tego dokumentu.

## 4. Co sprawdzić w następnym kroku

Testy integracyjne powinny objąć co najmniej:

- Pomyślny zapis pierwszej decyzji dla aktywnego żądania.
- Brak żądania.
- Żądanie wygasłe lub jeszcze nieaktywne (granice okna czasowego).
- Powtórny zapis po istniejącej decyzji, również po wygaśnięciu żądania.
- Dwie równoczesne decyzje operatorów o tym samym `request_id`: dokładnie jeden zapis.
- `ROLLBACK` i poprawne mapowanie błędów integralności.

## 5. Zasady pracy

- Pracujemy małymi krokami: jeden etap → cały aktualny plik → konkretna zmiana → test → analiza wyniku.
- Nie oznaczamy etapu jako **zweryfikowany**, dopóki nie zobaczymy wyniku odpowiednich testów.
- Kiedy pojawia się istotna decyzja lub przełom, asystent podaje gotowy fragment Markdown oznaczony **„Dodaj do `PROJECT_PROGRESS.md`:”**.
- Użytkownik wkleja fragment do tego pliku w repozytorium / plikach projektu.
- W nowej rozmowie warto udostępnić aktualny `PROJECT_PROGRESS.md` wraz z `PROJECT_BRIEF.md`.

## 6. Dziennik istotnych aktualizacji

### 2026-11-11 — Etap 1.7.8.11.28

- **Typ:** implementacja przygotowana, podmiana potwierdzona przez użytkownika.
- **Zakres:** `PostgresApprovalRepository.record_decision_once()`.
- **Decyzja:** transakcyjny `SELECT FOR UPDATE`, sprawdzenie aktywności po blokadzie, wymuszenie `UNIQUE(request_id)`.
- **Pozostało:** rzeczywiste testy integracyjne PostgreSQL i weryfikacja współbieżności.

### 2026-11-11 — Etap 1.7.8.11.28a: Reorganizacja testów

- **Status:** zakończony i zweryfikowany testami.
- **Decyzja architektoniczna:** podział testów na `tests/unit/` oraz `tests/integration/`.
- **Wykonane zmiany:**
  - Przeniesiono 22 pliki do `tests/unit/`.
  - Przeniesiono 2 pliki do `tests/integration/`.
  - Zachowano istniejącą konfigurację pytest.
  - Nie zmieniano logiki testów ani kodu aplikacji.
- **Weryfikacja:**
  - Testy jednostkowe: 913 passed.
  - Pełny pytest: 913 passed, 8 skipped, 0 failed.
  - Pominięte testy: 6 testów repozytorium PostgreSQL i 2 testy schematu.
- **Pozostało:** sprawdzenie śledzenia plików przez Git oraz uruchomienie testów integracyjnych na rzeczywistym PostgreSQL.
- **Następny etap:** `1.7.8.11.29` — testy integracyjne `PostgresApprovalRepository.record_decision_once()`.

### 2026-11-11 — Etap 1.7.8.11.29: Testy integracyjne record_decision_once()

- **Status:** zakończony i zweryfikowany na rzeczywistym PostgreSQL.
- **Zakres:** `PostgresApprovalRepository.record_decision_once()`.
- **Potwierdzone scenariusze:**
  - Pierwszy zapis decyzji dla aktywnego żądania.
  - Odrzucenie decyzji dla nieistniejącego żądania.
  - Odrzucenie decyzji dla wygasłego żądania, także przy cofniętym `decided_at`.
  - Odrzucenie decyzji przed początkiem okna aktywności.
  - Odrzucenie drugiej decyzji bez nadpisywania pierwszej.
  - Priorytet istniejącej decyzji nad wygaśnięciem żądania.
  - Równoczesne decyzje dwóch operatorów — dokładnie jeden skuteczny zapis.
  - Wygaśnięcie podczas oczekiwania na blokadę PostgreSQL.
  - ROLLBACK po nieoczekiwanym naruszeniu klucza głównego.
- **Wyniki testów:**
  - 913 testów jednostkowych — PASSED.
  - 15 testów integracyjnych repozytorium — PASSED.
  - 2 testy integracyjne schematu PostgreSQL — PASSED.
  - Pełna regresja: **930 passed, 0 failed, 0 skipped**.
- **Decyzja architektoniczna:** utrzymujemy transakcyjny zapis decyzji z `SELECT FOR UPDATE`, kontrolą czasu PostgreSQL po uzyskaniu blokady oraz `UNIQUE(request_id)`.
- **Pozostało:** przegląd zmian Git, commit i push.
- **Następny krok:** zakończenie wersjonowania implementacji PostgreSQL approval persistence.

### 2026-11-11 — Zakończenie PostgreSQL Approval Persistence

- **Status:** implementacja, testy integracyjne i wersjonowanie zakończone.
- **Pełna regresja:** 930 passed, 0 failed, 0 skipped.
- **Commit:** `097db9c`.
- **Git Push:** zakończony pomyślnie (`origin/main`).
- **Working tree:** clean.
- **Zakończone etapy:** `1.7.8.11.28`, `1.7.8.11.28a`, `1.7.8.11.29`.
- **Następny obszar:** integracja trwałego repozytorium zatwierdzeń z warstwą aplikacyjną i pozostałymi komponentami Human-in-the-Loop.

### 2026-11-11 — Etap 1.7.8.11.30: Composition Root

- **Status:** implementacja zakończona, testy i kontrola jakości zaliczone.
- **Nowe pliki:**
  - `src/ai_incident_commander/bootstrap.py`
  - `tests/unit/test_bootstrap.py`
- **Decyzje architektoniczne:**
  - Composition Root niezależny od FastAPI i LangGraph.
  - Jawne Dependency Injection przez istniejące porty aplikacyjne.
  - `ApprovalAuthorizer` jest wymagany — brak domyślnej autoryzacji `allow-all`.
  - `AsyncEngine` jest zarządzany przez asynchroniczny context manager i zamykany przez `dispose()`.
  - Zachowano rozdzielenie warstw application i infrastructure.
- **Weryfikacja:**
  - 5 nowych testów jednostkowych — PASSED.
  - Pełna regresja: 935 passed, 0 failed, 0 skipped.
  - Ruff linting — PASSED.
  - Ruff formatting — 56 plików poprawnie sformatowanych.
  - Mypy — 31 plików, brak błędów.
- **Ograniczenie:** nie przeprowadzono jeszcze testu integracyjnego `ApprovalApplicationService` utworzonego przez Composition Root na rzeczywistym PostgreSQL.
- **Następny krok:** commit i push, następnie integracyjny test pełnego cyklu zatwierdzania.

### 2026-11-11 — Etap 1.7.8.11.31: Integration Test Composition Root

- **Status:** implementacja testów i weryfikacja zakończone.
- **Nowy plik:** `tests/integration/test_bootstrap_integration.py`.
- **Zakres:** pełna integracja `approval_service_lifespan()` → `ApprovalApplicationService.decide()` → `PostgresApprovalRepository` → PostgreSQL.
- **Potwierdzone scenariusze:**
  - Uprawniony operator może zapisać decyzję.
  - Nieuprawniony operator otrzymuje `ApprovalPermissionDeniedError`, bez zapisu decyzji.
  - Ponowne utworzenie Composition Root nie pozwala nadpisać istniejącej decyzji (`ApprovalAlreadyDecidedError`).
- **Weryfikacja:**
  - Testy jednostkowe: 918 passed.
  - Testy integracyjne PostgreSQL: 20 passed.
  - Pełna regresja: **938 passed, 0 failed, 0 skipped**.
  - Ruff linting i formatowanie: PASSED.
  - Mypy: 31 plików, brak błędów.
- **Ograniczenie:** rzeczywisty mechanizm uwierzytelniania i produkcyjny adapter autoryzacji/RBAC nie są jeszcze zaimplementowane.
- **Pozostało:** commit i push.
- **Następny krok:** wybór kolejnego etapu rozwoju Human-in-the-Loop.