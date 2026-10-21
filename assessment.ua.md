# Вісімнадцять перевірок

Формат перевірки: **Запитання → Як виглядає добрий стан → Верифікація.**
Правило доказів: відповідь зараховується лише на тому рівні, для якого ви можете надати докази за запитом.

---

## Межа 1 — Досяжність (Reach) (ASI01, ASI02, ASI05, ASI08, ASI09)

### R1 — Чи працює якийсь агент з дефолтним сервісним акаунтом?

**Добре:** кожен робочий процес агента має виділену ідентичність (IAM agent identity або окремий SA на кожного агента); без базових ролей (`Owner`/`Editor`/`Viewer`).

```bash
gcloud projects get-iam-policy $PROJECT \
  --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members)" \
  --filter="bindings.members:compute@developer.gserviceaccount.com"
```

Будь-який рядок з `roles/editor` тут є знахідкою (finding).

### R2 — Чи обмежений IAM агента ресурсами, а не проєктом чи ієрархією папок?

**Добре:** агенти, MCP-інструменти та дані живуть в окремих проєктах; права надаються на рівні окремого датасету/бакета/секрету/субагента (`aiplatform.reasoningEngines.query`); ідентичності агентів не мають широких ролей на рівні проєкту або успадкованих прав через папки чи групи.

```bash
# 1. Пряма перевірка політики проєкту (очікується: порожньо)
gcloud projects get-iam-policy $PROJECT \
  --flatten="bindings[].members" \
  --filter="bindings.members:$AGENT_PRINCIPAL"

# 2. Перевірка рівня Примусово для Landing Zone: аналіз ефективного IAM через успадкування папок/організації
#    та розгортання груп, щоб переконатися, що агент не успадковує доступ до даних чи моделей
gcloud asset analyze-iam-policy \
  --organization=$ORG_ID \
  --identity="$AGENT_PRINCIPAL" \
  --expand-groups \
  --format="table(ACLs.resource, ACLs.role)"

# 3. Перевірка на наявність широких fleet-прив'язок (principalSet://) на домені довіри агентів
gcloud asset search-all-iam-policies \
  --scope="organizations/$ORG_ID" \
  --query="policy:agents.global.org-${ORG_ID}.system.id.goog"
```

### R3 — Чи увімкнено Workload Identity для кожного пулу нод?

**Добре:** кожен пул повідомляє про `GKE_METADATA`. Кластери Autopilot проходять це за замовчуванням (Примусово).

```bash
gcloud container node-pools list --cluster=$CLUSTER --region=$REGION \
  --format="table(name, config.workloadMetadataConfig.mode)"
```

### R4 — Чи виконується згенерований агентом код у пісочниці з блокуванням вихідного (egress) трафіку за замовчуванням?

**Добре:** ізольоване виконання gVisor (GKE Agent Sandbox або еквівалент); дозволені напрямки перелічені в `SandboxTemplate`; вихідний трафік за замовчуванням заблокований, окрім маршруту через AI-шлюз або Secure Web Proxy.

```bash
kubectl get pods -n $AGENT_NS \
  -o custom-columns="NAME:.metadata.name,RUNTIME:.spec.runtimeClassName"
```

### R5 — Чи є перевірка промптів та викликів інструментів обов'язковою мінімальною межею (floor) чи вибором?

**Добре:** налаштування floor для Model Armor примусово застосовані на рівні організації/папки/проєкту та вбудовані в AI-шлюз (вхідні промпти користувачів + вихідні виклики інструментів, відповіді інструментів та повідомлення A2A) з поведінкою fail-closed для невідомих типів контенту.

```bash
gcloud model-armor floorsettings describe \
  --full-uri="organizations/$ORG_ID/locations/global/floorSetting"

gcloud model-armor floorsettings describe \
  --full-uri="projects/$PROJECT/locations/global/floorSetting"
```

### R6 — Чи примусово застосовує платформа обмеження на запуск runaway-процесів та споживання токенів?

**Добре:** жорсткі ліміти тайм-ауту та кількості кроків у рантаймі (наприклад, `maxSteps` у Vertex AI Reasoning Engine), ліміти CPU/Memory контейнера, **ліміти токенів на кожного агента у шляху трафіку на AI-шлюзі** (прив'язані до верифікованої ідентичності агента, а не заголовка клієнта) та бюджети з обмеженням витрат (spend-cap) на проєкт як автоматичний запобіжник.

```bash
# 1. Перевірка лімітів ресурсів GKE для namespace виконання агентів
kubectl get limitrange -n $AGENT_NS -o yaml

# 2. Перевірка кроків/схем валідації Vertex AI Reasoning Engine
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${LOCATION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines" \
  | jq -r '.reasoningEngines[].spec.templates[] | select(.validationSchema != null)'

# 3. Перевірка політики лімітів токенів на шлюзі (наприклад, Agent Router / Envoy BackendTrafficPolicy або Apigee LLMTokenQuota)
kubectl get backendtrafficpolicy -A -o yaml | grep -A 15 "rateLimit:"
```

### R7 — Чи вимагають інструменти зміни стану підтвердження людиною, і чи позбавлені read-only інструменти прав на запис? (OWASP ASI09)

**Добре:** булевий прапорець розробника в коді (`readOnlyHint: True`) не може тихо вимкнути підтвердження людиною для інструменту, що змінює стан. Вважається **Примусовим**, коли виконуються всі чотири умови:
1. CI відхиляє будь-який MCP-інструмент без `readOnlyHint: true`, який явно не декларує `destructiveHint: true`.
2. Будь-яка зміна `readOnlyHint` вимагає повторного погодження в Agent Registry.
3. Інструменти для читання (read-only) та запису (write) працюють як окремі MCP-сервіси з окремими ідентичностями; read-only ідентичність має лише ролі читання на рівні даних, тому неправильно промаркований запис падає на рівні БД/сховища.
4. Red-team тест підтверджує, що кожен інструмент із правом запису запитує підтвердження користувача.

```bash
# 1. Перевірка, що ідентичність read-only MCP-сервісу не має жодних ролей запису/адміністрування у проєкті даних
gcloud asset analyze-iam-policy \
  --scope="projects/$DATA_PROJECT" \
  --identity="serviceAccount:$MCP_READONLY_SA" \
  --format="table(ACLs.resource, ACLs.role)" | grep -Ev "reader|viewer|metadataViewer"

# 2. Сканування оголошень MCP-інструментів у репозиторії на відсутність destructiveHint
grep -rn "@mcp.tool" .
```

---

## Межа 2 — Ідентичність та доступ (Identity & Access) (ASI03, ASI07, ASI10)

### I1 — Чи можете ви перелічити кожну ідентичність агента на платформі?

**Добре:** одна ідентичність на агента, названа за конвенцією, яку можна перелічити однією командою.
Найсильніша модель: [IAM ідентичність агента](https://docs.cloud.google.com/iam/docs/agent-identity-overview)
(`principal://agents.global.org-ORG_ID.system.id.goog/...` — принципал SPIFFE для кожного агента, прив'язаний до життєвого циклу, із токенами mTLS + DPoP) на Agent Platform runtime, Gemini Enterprise та Cloud Run; виділений сервісний акаунт на кожного агента через Workload Identity Federation у GKE.

```bash
# Сервісні акаунти для агентів (GKE WIF)
gcloud iam service-accounts list \
  --filter="displayName:agent" --format="table(email, displayName)"

# Agent Platform runtime: яку саме ідентичність має кожен агент
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${LOCATION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines" \
  | jq -r '.reasoningEngines[] | [.displayName, .spec.effectiveIdentity] | @tsv'
```

Значення `effectiveIdentity`, яке показує email сервісного акаунта у керованому рантаймі, означає, що цей агент був створений раніше або відмовився від нативної ідентичності агента.

### I2 — Чи мають якісь сервісні акаунти агентів експортовані ключі?

**Добре:** тиша. Агенти з нативною IAM-ідентичністю агента проходять цю перевірку за своєю конструкцією (експортованих ключів немає; токени прив'язані до сертифікатів і не підлягають повторному використанню поза межами середовища виконання) — рівень Примусово. Потім перевірте, чи ніхто не відмовився від прив'язування Context-Aware Access (CAA):

```bash
grep -rn "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES" .
```

Будь-яке входження, встановлене у `False`, є знахідкою.

```bash
for sa in $(gcloud iam service-accounts list --format="value(email)" --filter="displayName:agent"); do
  gcloud iam service-accounts keys list --iam-account=$sa \
    --managed-by=user --format="value(name)" | grep -q . && echo "КЛЮЧ ЗНАЙДЕНО: $sa"
done
```

Для рівня Примусово перевірте, що керовані організаційні політики заборони створення та завантаження ключів суворо активні:

```bash
for constraint in \
  iam.managed.disableServiceAccountKeyCreation \
  iam.managed.disableServiceAccountKeyUpload \
  iam.disableServiceAccountKeyCreation; do
  gcloud org-policies describe $constraint --project=$PROJECT --effective
done
```

### I3 — Чи відокремлено автентифікацію агента від автентифікації користувача?

**Добре:** інструменти, які торкаються даних користувача, вимагають делегованих облікових даних користувача (OAuth-токен) у шляху виклику разом з ідентичністю агента/сервісу (`X-Serverless-Authorization` на стандартних URL `*.run.app`); власна ідентичність агента не може читати дані користувача самостійно.
**Верифікація:** аналіз коду та політик шлюзу — надайте посилання на реалізації інструментів та негативні тести. Доказом є код і тест, а не діаграма.

### I4 — Чи перевіряють ваші агенти, з ким вони розмовляють?

**Добре:** міжагентний трафік через mTLS / DPoP (Agent Gateway або mesh); кінцеві точки A2A відхиляють непідписані `AgentCard` або карти, підписані поза корпоративним коренем довіри; делегування від батьківського агента до субагента використовує вузьку роль `aiplatform.reasoningEngines.query` на конкретного субагента, а не `roles/aiplatform.user` на весь проєкт.
**Верифікація:** спробуйте виконати неавтентифікований або непідписаний обмін картами з production кінцевою точкою A2A в обхід шлюзу. Це має зазнати невдачі до делегування задачі.

### I5 — Чи є примусовий реєстр серверів MCP із визначеними власниками?

**Добре:** приватний Agent Registry (або API hub / перевірений через GitOps список бекендів шлюзу) кожної кінцевої точки MCP із власником; `run.managed.requireInvokerIam` увімкнено на рівні організації (жодних `allUsers`); `discoveryengine.managed.disableCustomMcpServerConnector` увімкнено на рівні організації та послаблено лише у виділеному хаб-проєкті Gemini Enterprise разом із `allowedDataSources` та `allowedEgressFqdns`.

```bash
gcloud org-policies describe run.managed.requireInvokerIam --project=$MCP_PROJECT --effective
gcloud org-policies describe discoveryengine.managed.disableCustomMcpServerConnector --organization=$ORG_ID
```

**Верифікація:** виберіть кінцеву точку MCP або FQDN, яких немає у списку дозволених, і підтвердьте, що агент не може до них звернутися.

### I6 — Чи є логи виконання та викликів інструментів захищеними від видалення (tamper-proof)?

**Добре:** всі промпти, проміжні думки, виклики інструментів та повідомлення A2A записуються шлюзом/платформою (поза межами досяжності контейнера агента) безпосередньо в заблокований, незмінний лог-бакет у виділеному проєкті безпеки (`prj-sec-logging`) з активним блокуванням політики утримання (Retention Policy Lock). Навіть власники проєкту не можуть видалити ці логи протягом вікна утримання.

```bash
gcloud logging buckets describe $BUCKET_ID --location=$LOCATION --project=$SEC_LOGGING_PROJECT \
  --format="table(name, retentionDays, locked)"
```

Результат проходження на рівні Примусово: `locked: true` та `retentionDays > 0`.

---

## Межа 3 — Походження (Provenance) (ASI04, ASI06)

### P1 — Чи закріплені версії моделей за дайджестом або незмінним GA ID (і чи контролюються вони списком дозволених моделей організації)?

**Добре:** відсутність аліасів `-latest` або `-preview` у маніфестах продакшену; організаційна політика `vertexai.allowedModels` на папці продакшену дозволяє лише `:predict` для затверджених GA-моделей (без `:tune` та `:deploy`) і переглядається щомісяця відповідно до графіка виведення моделей з експлуатації.

```bash
gcloud org-policies describe vertexai.allowedModels --folder=$PROD_AI_FOLDER_ID
```

**Верифікація:** пошук за допомогою grep у маніфестах розгортання та перевірка активної політики `vertexai.allowedModels`.

### P2 — Чи існує єдиний шлях до продакшену для моделей та сервісів Cloud Run?

**Добре:** інфраструктура обслуговування завантажує образи та моделі лише з одного засвідченого реєстру; доступ на запис має тільки SA пайплайну; політика `run.managed.disableInlinedSource` примусово забороняє розгортання Cloud Run із неперевіреного локального вихідного коду.

```bash
gcloud storage buckets get-iam-policy gs://$MODEL_BUCKET \
  --format="table(bindings.role, bindings.members)"

gcloud org-policies describe run.managed.disableInlinedSource --project=$PROJECT --effective
```

Користувачі з роллю `objectAdmin` є альтернативними шляхами до продакшену.

### P3 — Чи є контейнер обслуговування засвідченим?

**Добре:** Binary Authorization у режимі `ENFORCED_BLOCK_AND_AUDIT_LOG` на кластері GKE та примусово застосований для Cloud Run через організаційну політику `run.allowedBinaryAuthorizationPolicies`.

```bash
gcloud container binauthz policy export
gcloud org-policies describe run.allowedBinaryAuthorizationPolicies --folder=$AI_WORKLOADS_FOLDER_ID
```

### P4 — Чи викликає оновлення версії моделі поведінковий diff?

**Добре:** набір регресійних тестів безпеки (evals) як *обов'язковий* крок у CI на staging-середовищі перед тим, як нова GA-модель додається до політики `vertexai.allowedModels` у продакшені; diff переглядається так само, як diff коду.
**Верифікація:** конфігураційний файл CI. Якщо людина може просунути модель без проходження тестів, контроль є Налаштованим, а не Примусовим.

### P5 — Чи розглядається пам'ять агента як вхідна поверхня (та чи захищена вона ключами CMEK)?

**Добре:** записи в пам'ять або сховище RAG прив'язані до джерела з можливістю масового видалення за джерелом; джерела заземлення (grounding) у продакшені обмежені політиками `vertexai.genAIGroundingSources` та `vertexai.disableGenAIGoogleSearchGrounding`; Memory Bank / Sessions / Vector Search зашифровані ключами CMEK (`gcp.restrictNonCmekServices`) на регіональних або мультирегіональних ендпоінтах.
**Верифікація:** простежте один запис у пам'яті до його джерела та перевірте активність `gcp.restrictNonCmekServices` на проєкті даних.

---

## Тест на обхід шлюзу та лендінг-зони (Gateway & Landing Zone Bypass Test)

Шлюз або лендінг-зона на архітектурній діаграмі — це рівень **Налаштовано**. Контролі, що покладаються на шлюз (`R5`, `R6`, `I3`, `I4`, `I5`, `I6`), зараховуються як **Примусово** лише тоді, коли середовище виконання агента не має жодного способу обійти шлюз. Виконайте ці перевірки для кожного робочого навантаження агента; якщо будь-яка з них провалюється, знизьте рівень залежних перевірок до **Налаштовано**.

### 1. Відсутність прямого виходу в інтернет або до провайдера моделей
- **У GKE / Cloud Run:** `NetworkPolicy` із забороною за замовчуванням та правила VPC-фаєрволу блокують усе, крім AI-шлюзу / Secure Web Proxy; політика `run.allowedVPCEgress = all-traffic` примусово спрямовує весь трафік Cloud Run у VPC.
- **У керованому рантаймі Agent Platform:** проєкт рантайму **обов'язково** має перебувати всередині активного периметра **VPC Service Controls** (`aiplatform.googleapis.com`, `discoveryengine.googleapis.com`, `modelarmor.googleapis.com` тощо) із маршрутизацією приватного трафіку через інтерфейси Private Service Connect (PSC-I) та Secure Web Proxy. Поза межами периметра VPC-SC керований рантайм виходить в інтернет напряму з тенант-мережі Google, повністю оминаючи ваш VPC-фаєрвол.

```bash
# Перевірка в GKE: прямий виклик провайдера з поду агента має завершуватися тайм-аутом (а не HTTP-кодом)
kubectl exec -n $AGENT_NS deploy/$AGENT -- curl -sS -m 5 -o /dev/null -w '%{http_code}\n' \
  https://generativelanguage.googleapis.com/

# Перевірка керованого рантайму та Cloud Run: периметр VPC-SC захищає aiplatform та run у продакшені
gcloud access-context-manager perimeters describe $PROD_PERIMETER \
  --policy=$ACCESS_POLICY_ID --format="yaml(status.restrictedServices, status.resources)"
```

### 2. Ключі та доступи до моделей належать шлюзу — агент не має прямих чи успадкованих IAM-прав на виклик моделей
Агент без прямої ролі у своєму проєкті все одно може успадкувати дозвіл `aiplatform.endpoints.predict` від папки, Google-групи або через fleet-прив'язку `principalSet://` на домені довіри.

```bash
# 2a. Відсутність ключів API або секретів інструментів у змінних середовища контейнера агента
kubectl exec -n $AGENT_NS deploy/$AGENT -- env | grep -Ei 'api[_-]?key|secret|password|token'

# 2b. Повний аналіз ієрархії IAM із розгортанням груп через Cloud Asset Inventory (очікується: нуль прав aiplatform.endpoints.predict у ідентичності агента; право виклику має лише SA шлюзу)
gcloud asset analyze-iam-policy \
  --organization=$ORG_ID \
  --identity="$AGENT_PRINCIPAL" \
  --permissions="aiplatform.endpoints.predict" \
  --expand-groups
```

### 3. Агент не може змінити політики шлюзу чи захисних фільтрів (і фільтрація працює у режимі fail-closed)

```bash
# Ідентичність агента не може редагувати маршрути або RBAC-політики шлюзу
kubectl auth can-i update agentgatewaypolicies.agentgateway.dev \
  -n agentgateway-system --as=system:serviceaccount:$AGENT_NS:$AGENT_KSA   # очікується: no
```
