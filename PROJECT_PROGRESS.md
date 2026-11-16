# AI Incident Commander — Project Progress

> **Cel:** zwięzła pamięć techniczna projektu, umożliwiająca wznowienie pracy w nowej konwersacji.
> **Dokument nadrzędny:** `PROJECT_BRIEF.md` — wizja, wymagania i roadmapa.
> **Zasada aktualizacji:** wpisy przy istotnych kamieniach milowych architektury, zmianach kontraktów i decyzjach bezpieczeństwa; historia drobnych zmian należy do Git.
> **Priorytet dowodów:** aktualne pliki repozytorium i wyniki poleceń > dokument checkpointu. Nie oznaczamy planów jako wdrożonych.

## 1. Aktualny stan projektu

- **Obszar:** **Phase 2.0 — LangGraph Core**. Podetapy **2.0.1–2.0.3** zakończone i zapisane w Git; **2.0.4 — Investigation Planning & Workflow Routing** technicznie zakończony (implementacja, testy lokalne, pełna regresja), oczekuje na aktualizację dokumentacji i commit/push.
- **Ostatni kamień milowy:** `InvestigationPlanSnapshot` w `IncidentState`, walidowany plan diagnostyczny, wstrzykiwany asynchroniczny planner (domyślnie deterministyczny) i routing wybierający `logs`, `metrics` albo obie gałęzie. Agregacja następuje po wykonaniu wybranych kolektorów.
- **Stan orkiestracji:** `IncidentState` jest niezależny od domenowego `Incident`; przechowuje serializowalne snapshoty incydentu, dowodów i hipotez oraz opcjonalny `investigation_plan`. `merge_evidence()` deduplikuje po `evidence_id`, zapewnia deterministyczny porządek i odrzuca konflikty treści. Plan pozostaje polem *single-writer*, bez reducera.
- **Weryfikacja Phase 2.0.4 (2026-11-16):** **42 passed** w dwóch plikach testowych stanu i grafu; Ruff lint **PASSED**, Ruff format **118 plików już sformatowanych**, Mypy strict **54 pliki, 0 błędów**. Przetestowano m.in. dobór źródeł, współbieżność, synchronizację, pojedynczą agregację, walidację planu i bezpieczne scalanie dowodów.
- **Ostatnia potwierdzona pełna regresja:** **1472 passed, 0 failed** (2026-11-16; 44,49 s; `RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1`, z testami PostgreSQL). Wzrost o 16 testów względem ostatniej pełnej regresji 2.0.3 (**1456 passed**).
- **LangGraph:** według przebiegu prac dodano wersję **1.2.22** przez `uv`; bez podłączonego LLM/MCP, trwałych checkpointów i automatycznych retry. Bieżący graf służy diagnostyce i nie wykonuje mutujących działań.
- **Zachowane zabezpieczenia remediation/MCP:** `apv:v2`, Guard, durable dispatch i kontrakt `SecureMcpExecutor` pozostają odrębną warstwą; rzeczywisty executor MCP i efekty zewnętrzne nadal **nie są** zaimplementowane.
- **PostgreSQL / Alembic:** ostatnio potwierdzony lokalny stan `e62b4f0c91ad (head)` — dopuszczono `apv:v1`/`apv:v2` w dwóch `CHECK`; 6 testów schematu zaliczonych (2026-11-15).
- **Git:** Phase 2.0.3 zatwierdzony i wypchnięty jako **`592c5ef`** (`feat(orchestration): add initial parallel LangGraph incident workflow`); po push potwierdzono `main...origin/main` oraz czyste drzewo. **Stan Git po zmianach 2.0.4 nie został jeszcze ponownie sprawdzony** — nie zakładać stagingu, commita ani synchronizacji nowych zmian.
- **Teraz:** zapisać ten kamień milowy w dokumentacji, sprawdzić rzeczywisty `git status` i diff 2.0.4, uzgodnić staging, commit/push i potwierdzić synchronizację. Następnie wybrać kolejny mały krok LangGraph Core na podstawie aktualnych pełnych plików, bez rozpoczynania transportu MCP.

## 2. Kluczowe decyzje i granice bezpieczeństwa

- **Approval i HITL:** decyzja `APPROVED` pochodzi z PostgreSQL, nie od klienta, LLM lub MCP. `record_decision_once()` korzysta z transakcji, `SELECT ... FOR UPDATE`, czasu PostgreSQL i `UNIQUE(request_id)`; produkcyjna autentykacja/RBAC nadal jest do zrobienia.
- **Identyfikacja zatwierdzonego zakresu:** zaufany Preflight waliduje katalog akcji i aktualną tożsamość zasobu; `afp:v2` obejmuje krok, parametry, `ResolvedTarget` i `policy_version`. Guard tworzy świeży, spójny `VerifiedExecutionContext(scope, target)`.
- **Polityka `apv:v1` vs `apv:v2`:** `apv:v1` wiąże wyłącznie `ActionCatalog` (historia/legacy), a `apv:v2` także `binding_version` rejestru `TrustedMcpActionBindings` (`action_name → server_id → tool_name`). Zmiana mapowania zmienia wersję i fingerprint; nowe jawne ścieżki MCP fail-closed wobec `apv:v1`/braku bindings.
- **Kompatybilność:** modele Approval Request i Execution Claim, walidacja fingerprintu i PostgreSQL odczytują/akceptują oba formaty, ale **poprawny historyczny rekord nie jest automatycznie uprawnieniem do mutującego MCP**. Osobne `validate_mcp_bound_remediation_preflight()`, ścieżki serwisów request/Guard i MCP Composition Root wymuszają `apv:v2` dla workflow MCP.
- **Granica konfiguracji:** `mcp_approval_workflow_lifespan()` wymaga spójnego, niepustego rejestru i podaje tę samą instancję do creation i Guard. Sam Composition Root nie zapobiega ręcznej konstrukcji niespójnych serwisów poza nim; executor musi być osobno ograniczony i uprzywilejowany.
- **Atomic Execution Claim:** `UNIQUE(plan_id, step_id)` i `UNIQUE(request_id)`, ponowna transakcyjna weryfikacja zatwierdzenia/zakresu, zegar PostgreSQL. Guard / claim nie wywołują MCP.
- **Execution Lifecycle / recovery:** trwałe `EXECUTING → SUCCEEDED / FAILED / UNKNOWN`, jeden `RemediationExecution` na claim (`UNIQUE(claim_id)`). `RemediationExecutionRecoveryService` może uruchomić wyłącznie istniejący claim, który **nie ma jeszcze execution**, po świeżym Guard i osobnej polityce wieku claimu; nie ponawia `EXECUTING` lub `UNKNOWN`.
- **Verified Dispatch:** `RemediationTrustedDispatchService` pobiera istniejący claim i execution, ponownie weryfikuje Guard, po czym wywołuje atomowe `reserve_verified_once()` w PostgreSQL. Adapter blokuje execution, sprawdza `EXECUTING`, zgodność scope/claim/approval oraz `UNIQUE(execution_id)`. **Usunięto stare `reserve_once()` i niezabezpieczony port**; `get_by_execution_id()` to odczyt. Istniejący dispatch nie jest uprawnieniem do MCP.
- **Kontrakt wykonania MCP, bez implementacji:** `SecureMcpExecutor.execute_for_step(request_id, step)` nie bierze od wywołującego `dispatch_id`, `execution_id` ani `VerifiedExecutionScope` jako praw do wykonania. `McpInvocationResult` rozróżnia `ACKNOWLEDGED`, `REJECTED`, `UNKNOWN`; ACK nie oznacza zweryfikowanego usunięcia incydentu.
- **Granice systemów rozproszonych:** PostgreSQL zapewnia jednorazową **rezerwację**, nie exactly-once efektu zewnętrznego. Po crashu/timeout brak automatycznego retry mutującego MCP; wymagane będą downstream idempotency, preconditions i reconciliation. `server_id` to alias — zmiana endpointu/poświadczeń/semantyki za aliasem nie musi zmieniać `binding_version`; przed prawdziwym MCP potrzebne pinning i integralność konfiguracji.
- **Brak produkcyjnych efektów MCP:** brak gotowego wykonawcy, klienta/serwerów MCP, gwarantowanego authorization boundary w systemie docelowym, LangGraph durable resume oraz produkcyjnego RBAC/auth. Niczego z tego nie oznaczamy jako ukończone.
- **LangGraph ↔ domena:** `Incident` pozostaje źródłem reguł biznesowych (w tym kontrolowanego przejścia do `RESOLVED`); `IncidentState` to stan orkiestracji, bez połączeń DB, klientów MCP czy sekretów. Reducer dowodów scala wyniki gałęzi, ale sam nie zapewnia idempotencji operacji zewnętrznych ani durable execution.

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
- Dodano `RemediationDispatch`, początkowo z historycznym `reserve_once()`; w kolejnym kamieniu milowym usunięto tę słabszą ścieżkę na rzecz `reserve_verified_once()`. Rezerwacja jest zatwierdzana przed potencjalną próbą MCP; ponowna rezerwacja kończy się odmową.
- Nowa tabela `remediation_dispatches`: PK `dispatch_id`, FK `execution_id` z `ON DELETE RESTRICT`, `UNIQUE(execution_id)`, `reserved_at` z zegara PostgreSQL. Migracja `c4f8a2d7e951` zastosowana, test schematu zaliczony.
- Testy PostgreSQL obejmują konkurencję **reserve vs reserve** i **reserve vs outcome**. **Ówczesna regresja: 1225 passed; Ruff/Mypy: PASSED**. **Późniejszy commit/push:** `4aaa1ff` (`Durable MCP Dispatch Reservations`).
- **Granica:** rezerwacja jest trwałym faktem, nie zdarzeniem wysłania ani uprawnieniem do wykonania MCP. Trusted Dispatch Service dodano później; nadal brak realnego MCP Executora i reconciliation.

### 2026-11-15 — Trusted Dispatch i usunięcie słabszego API

- Dodano `RemediationTrustedDispatchService`, `ReservedVerifiedDispatch` oraz rezerwację przez transakcyjne `reserve_verified_once(execution_id, verified_scope)` — atomowe sprawdzenie `EXECUTING`, claimu, zgody i zakresu.
- Zweryfikowano w PostgreSQL odporność na duplikaty i niezgodny zakres; całkowicie usunięto wcześniejsze `reserve_once()` z publicznych kontraktów i adaptera. **Pełna regresja po usunięciu: 1274 passed; Ruff/Mypy PASSED.**
- **Commit/push:** `d07f563` (`Trusted Dispatch Authorization`) oraz `7d49058` (`Remove Unverified Dispatch Reservation`) — potwierdzone na `origin/main`.

### 2026-11-15 — MCP-bound Policy v2, Approval Integrity i kompatybilna migracja

- Zaimplementowano `TrustedMcpActionBindings` z `binding_version` oraz `create_mcp_bound_action_policy_version()` generujące `apv:v2` na podstawie zaufanego katalogu i mapowań; legacy `apv:v1` zachowano dla historii.
- Dopuszczono oba formaty w modelach i `action_fingerprint.py` bez zmiany hasha `afp:v2`. Dodano migrację `e62b4f0c91ad` zmieniającą tylko dwa `CHECK` w PostgreSQL; lokalny upgrade i **6 testów schematu** zaliczone.
- Dodano MCP-bound Preflight, Approval Request Creation oraz świeży Approval Guard; zaufane mapowanie jest sprawdzane podczas tworzenia i ponownej weryfikacji zatwierdzenia. PostgreSQL E2E do `Verified Dispatch`: **37 passed**, w tym odmowy po zmianie `tool_name`, `server_id`, `resource_id` oraz dla historycznego `apv:v1` na ścieżce MCP.
- Zaktualizowano legacy testy walidacji `apv:v2`. **Pełna regresja na tym etapie: 1400 passed, 0 failed** (z aktywnymi testami PostgreSQL). **Commit/push tej nowej grupy zmian: jeszcze niepotwierdzone**.

### 2026-11-15 — MCP-bound Composition Root, kontrakt Executora i dokumentacja ADR

- Dodano `mcp_approval_workflow_lifespan()` — wspólne bindings dla tworzenia requestów i Guard; **25 testów** w dwóch plikach Bootstrap zaliczonych.
- Dodano `SecureMcpExecutor` Protocol / `McpInvocationResult` z rezultatami `ACKNOWLEDGED`, `REJECTED`, `UNKNOWN`; **17 testów** zaliczonych. Bez transportu MCP, retry ani realnych efektów.
- Ostatni Ruff lint / format / Mypy: **PASSED** (114 sformatowanych plików, 52 pliki źródłowe).
- Przygotowano `README.md` i `docs/adr/0001-mcp-bound-approval-policy-versioning.md`, które **uczciwie** opisują rzeczywistą, niewcześniej zaplanowaną ewolucję `apv:v1 → apv:v2`, powody i koszty migracji oraz ograniczenia. Stan dodania do repo i commit należy potwierdzić.

### 2026-11-16 — Phase 2.0.1–2.0.3: IncidentState i pierwszy równoległy LangGraph

- **2.0.1 — audyt:** potwierdzono gotowość istniejącego stacku Python 3.12 do wprowadzenia orkiestracji; zależności AI dodawane stopniowo, na początku tylko LangGraph (w przebiegu prac: 1.2.22).
- **2.0.2 — stan:** zaimplementowano `IncidentState` oparty na `TypedDict` / `Annotated`, serializowalne snapshoty danych domenowych oraz `merge_evidence()` deduplikujący po stabilnym `evidence_id` bez mutowania danych. Domena i jej reguły przejść nie zostały zmienione.
- **2.0.3 — graf:** `START → intake → collect_logs || collect_metrics → aggregate_evidence → END`. Asynchroniczne wstrzykiwane kolektory, walidacja `incident_id`, oczekiwanie agregatora na obie gałęzie i scalanie dowodów przez reducer. Dane zewnętrzne, LLM, retry i trwałe checkpointy pozostają poza zakresem pierwszego grafu.
- **Testy i typowanie:** **26 passed** (12 testów grafu + 14 stanu), Ruff lint/format **PASSED** (118 plików), Mypy strict **PASSED** (54 pliki, bez błędów). **Pełna regresja po zmianach: 1456 passed, 0 failed (2026-11-16, 22,57 s, z aktywnymi testami PostgreSQL).**
- **Repozytorium:** commit/push **`592c5ef`** na `main`/`origin/main` potwierdzony 2026-11-16; po zakończeniu 2.0.3 drzewo Git było czyste.


### 2026-11-16 — Phase 2.0.4: Investigation Planning & Workflow Routing

- **2.0.4.1 — kontrakt planu:** dodano `InvestigationPlanSnapshot` (`sources`, `rationale`) i `investigation_plan: InvestigationPlanSnapshot | None` do `IncidentState`; `initial_incident_state()` ustawia `None`. Walidacja odrzuca pusty plan, duplikaty i nieobsługiwane źródła; plan nie ma reducera (*single-writer*).
- **2.0.4.2 — planner:** dodano node planowania oraz wstrzykiwany asynchroniczny `InvestigationPlanner`. Domyślny deterministyczny planner wybiera `logs` i `metrics`. Wyjście planera jest walidowane ponownie przed zebraniem dowodów; wejściowy snapshot incydentu pozostaje izolowany od zmian planera.
- **2.0.4.3 — routing:** plan steruje wyborem `collect_logs`, `collect_metrics` albo obu kolektorów. Zmodyfikowano synchronizację tak, aby agregacja działała także dla jednej wybranej gałęzi i wykonywała się jednokrotnie. Przy dwóch źródłach zachowano równoległość i reducer `merge_evidence()`.
- **Weryfikacja:** **42 passed** w testach stanu i grafu; Ruff lint **PASSED**, Ruff format **118 plików**, Mypy strict **54 pliki, 0 błędów**. **Pełna regresja: 1472 passed, 0 failed (2026-11-16, 44,49 s, z testami PostgreSQL).**
- **Granice:** brak LLM, MCP, trwałych checkpointów, automatycznych retry i efektów mutujących. **Status Git tej grupy zmian do sprawdzenia przed commitem**.

## 4. Pozostały zakres i następny krok Phase 2.0

**Zamknięcie 2.0.4 w repo:** implementacja, testy grafu, Ruff, Mypy i pełna regresja PostgreSQL zakończone pomyślnie. Należy sprawdzić bieżący stan Git, przejrzeć diff (`incident_state.py`, `incident_graph.py`, testy i dokumentacja — rzeczywisty zakres ustalić przez `git status`), świadomie dodać zmiany do stagingu, wykonać commit/push i potwierdzić synchronizację `main`/`origin/main`. Nie utożsamiać zielonych testów z zapisaniem zmian w Git.

**Dalszy LangGraph Core:** po zamknięciu 2.0.4 iteracyjnie rozwijać orkiestrację (kolejne źródła dowodów, subgrafy, checkpointing/durable execution oraz kontrolowana obsługa błędów i retry). `interrupt()` i bezpieczne wznowienie Human-in-the-Loop pozostają do wdrożenia we właściwym etapie. Kolejny zakres ustalić po analizie całych aktualnych plików; nie traktować planów jako implementacji.

**Odłożone do właściwych faz:** bezpieczny executor MCP i gateway, pinning/integralność konfiguracji serwerów, resource preconditions, downstream idempotency i reconciliation `UNKNOWN`, klienci/serwery MCP, zaawansowany RAG, obserwowalność, CI/CD oraz wdrożenie. PostgreSQL nie gwarantuje exactly-once skutków zewnętrznych.

**Dokumentacja:** zachować uczciwy opis ewolucji `apv:v1 → apv:v2` w README i `docs/adr/0001-mcp-bound-approval-policy-versioning.md`. `PROJECT_PROGRESS.md` aktualizować przy kamieniach milowych; `SESSION_HANDOFF.md` służy wznowieniu kontekstu, nie rejestrowaniu każdej drobnej zmiany.

## 5. Wznowienie pracy i zasady współpracy

- Zawsze analizujemy **cały aktualny plik** przed zmianą; nie zakładać, że snapshot checkpointu to kod repozytorium.
- Iteracyjnie: jedna mała zmiana → testy → analiza wyniku; maksymalnie **8 plików testowych w partii**.
- Pełna regresja na lokalnym PostgreSQL (Docker uruchomiony):

  ```bash
  RUN_DB_APPROVAL_TESTS=1 RUN_DB_SCHEMA_TESTS=1 \
  uv run --env-file .env pytest -q
  ```

- Kontrole jakości: `uv run ruff check src/ tests/ migrations/versions/`, `uv run ruff format --check src/ tests/ migrations/versions/`, `uv run mypy src/ai_incident_commander/`.
- Git: `git status --short` i `git diff --stat` **nie obejmują** rozmiaru untracked; staged diff sprawdzamy przez `git diff --cached --check` / `--stat`.
- `PROJECT_PROGRESS.md` aktualizujemy przy kamieniach milowych; `SESSION_HANDOFF.md` odświeżamy przy zamknięciu etapu lub przed nową konwersacją. Oddzielać implementację, testy, repozytorium Git i produkcyjne uruchomienie.
