# Сімнадцять перевірок

Формат перевірки: **Запитання → Як виглядає добрий стан → Верифікація.**
Правило доказів: відповідь зараховується лише на тому рівні, для якого ви можете надати докази за запитом.

---

## Межа 1 — Досяжність (Reach) (ASI01, ASI02, ASI05, ASI08)

### R1 — Чи працює якийсь агент з дефолтним сервісним акаунтом?

**Добре:** кожен робочий процес агента має виділений SA (сервісний акаунт); без базових ролей (Owner/Editor/Viewer).

```bash
gcloud projects get-iam-policy $PROJECT \
  --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members)" \
  --filter="bindings.members:compute@developer.gserviceaccount.com"
```

Будь-який рядок з `roles/editor` тут є знахідкою (finding).

### R2 — Чи обмежений IAM агента ресурсами, а не проектом?

**Добре:** гранти на рівні датасету/бакета/секрету; SA агентів відсутні в політиці на рівні проекту.

```bash
gcloud projects get-iam-policy $PROJECT \
  --flatten="bindings[].members" \
  --filter="bindings.members:$AGENT_SA"
```

Результат проходження на рівні проекту: порожній.

### R3 — Чи увімкнено Workload Identity для кожного пулу нод?

**Добре:** кожен пул повідомляє про `GKE_METADATA`. Кластери Autopilot проходять це за замовчуванням (Примусово).

```bash
gcloud container node-pools list --cluster=$CLUSTER --region=$REGION \
  --format="table(name, config.workloadMetadataConfig.mode)"
```

### R4 — Чи виконується згенерований агентом код у пісочниці з блокуванням вихідного (egress) трафіку за замовчуванням?

**Добре:** ізольоване виконання gVisor (GKE Agent Sandbox або еквівалент); дозволені напрямки перелічені в `SandboxTemplate`.

```bash
kubectl get pods -n $AGENT_NS \
  -o custom-columns="NAME:.metadata.name,RUNTIME:.spec.runtimeClassName"
```

### R5 — Чи є перевірка промтів обов'язковою мінімальною межею (floor) чи вибором?

**Добре:** налаштування floor для Model Armor на рівні організації чи проекту — мінімум, від якого жодна команда не може відмовитися.

```bash
gcloud model-armor floorsettings describe \
  --full-uri="projects/$PROJECT/locations/global/floorSetting"
```

### R6 — Чи примусово застосовує платформа обмеження на запуск runaway-процесів та споживання токенів?

**Добре:** жорсткі ліміти тайм-ауту на виконання, максимальна кількість кроків (наприклад, `maxSteps` у Vertex AI Reasoning Engine) та ліміти CPU/Memory контейнера для запобігання відмові в обслуговуванні, вичерпанню ресурсів або неконтрольованому зростанню витрат на API.

```bash
# Перевірка лімітів ресурсів GKE для namespace виконання агентів
kubectl get limitrange -n $AGENT_NS -o yaml

# Перевірка кроків/схем валідації Vertex AI Reasoning Engine
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${LOCATION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines" \
  | jq -r '.reasoningEngines[].spec.templates[] | select(.validationSchema != null)'
```

---

## Межа 2 — Ідентичність та доступ (Identity & Access) (ASI03, ASI07, ASI10)

### I1 — Чи можете ви перелічити кожну ідентичність агента на платформі?

**Добре:** одна ідентичність на агента, названа за конвенцією, яку можна перелічити однією командою. Найсильніша модель: [IAM ідентичність агента](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/agent-identity) (принципал SPIFFE для кожного агента, прив'язаний до життєвого циклу) замість сервісних акаунтів.

```bash
# Сервісні акаунти для агентів
gcloud iam service-accounts list \
  --filter="displayName:agent" --format="table(email, displayName)"

# Agent Runtime: яку саме ідентичність має кожен агент
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${LOCATION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines" \
  | jq -r '.reasoningEngines[] | [.displayName, .spec.effectiveIdentity] | @tsv'
```

Значення `effectiveIdentity`, яке показує email сервісного акаунта, означає, що цей агент був створений раніше або відмовився від ідентичності агента.

### I2 — Чи мають якісь сервісні акаунти агентів експортовані ключі?

**Добре:** тиша. Агенти з ідентичністю IAM агента проходять цю перевірку за своєю конструкцією (експортованих ключів немає; токени прив'язані до сертифікатів і не підлягають повторному використанню поза межами середовища виконання) — рівень Примусово. Потім перевірте, чи ніхто не відмовився від прив'язування CAA:

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

Для рівня Примусово перевірте, що організаційні політики створення ключів є суворо активними:
```bash
gcloud resource-manager org-policies describe iam.disableServiceAccountKeyCreation \
  --project=$PROJECT --effective
```

### I3 — Чи відокремлено автентифікацію агента від автентифікації користувача?

**Добре:** інструменти, які торкаються даних користувача, вимагають делегованих облікових даних користувача в шляху виклику; власний SA агента не може читати дані користувача самостійно.
**Верифікація:** аналіз коду — надайте посилання на реалізації інструментів. Доказом є код, а не діаграма.

### I4 — Чи перевіряють ваші агенти, з ким вони розмовляють?

**Добре:** міжагентний трафік через mTLS (mesh або Agent Gateway); кінцеві точки A2A відхиляють непідписаних/неавтентифікованих пірів; немає шляху між агентами в обхід шлюзу.
**Верифікація:** спробуйте виконати неавтентифікований обмін картами з production кінцевою точкою A2A з-поза меж mesh. Це має зазнати невдачі на транспортному рівні.

### I5 — Чи є реєстр серверів MCP з визначеними власниками?

**Добре:** реєстр (реєстр шлюзу або перевірений YAML у git) кожної кінцевої точки MCP з вказанням власника; правила вихідного трафіку (egress) блокують неперелічені кінцеві точки.
**Верифікація:** виберіть кінцеву точку MCP, якої немає в списку, і підтвердьте, що под агента не може її досягти.

### I6 — Чи є логи виконання та викликів інструментів захищеними від видалення (tamper-proof)?

**Добре:** всі промти, проміжні думки, виклики інструментів та відповіді записуються безпосередньо в заблокований, імутабельний лог-бакет з активним блокуванням політики утримання (Retention Policy Lock). Навіть власники проекту не можуть видалити ці логи протягом вікна утримання.

```bash
gcloud logging buckets describe $BUCKET_ID --location=$LOCATION --project=$PROJECT \
  --format="table(name, retentionDays, locked)"
```

Результат проходження на рівні Примусово: `locked: true` та `retentionDays > 0`.

---

## Межа 3 — Походження (Provenance) (ASI04, ASI06)

### P1 — Чи закріплені версії моделей за дайджестом (digest)?

**Добре:** відсутність тегів `latest` у посиланнях на моделі; оновлення є подіями імпорту.
**Верифікація:** пошук за допомогою grep у маніфестах розгортання та посиланнях на реєстри. Доказом є маніфест у git.

### P2 — Чи існує один шлях до продакшену для моделей?

**Добре:** інфраструктура обслуговування завантажує дані лише з одного реєстру; доступ на запис має тільки SA пайплайну імпорту.

```bash
gcloud storage buckets get-iam-policy gs://$MODEL_BUCKET \
  --format="table(bindings.role, bindings.members)"
```

Користувачі з роллю `objectAdmin` є альтернативними шляхами до продакшену.

### P3 — Чи є контейнер обслуговування засвідченим?

**Добре:** Binary Authorization у режимі `ENFORCED_BLOCK_AND_AUDIT_LOG` на кластері обслуговування.

```bash
gcloud container binauthz policy export
```

### P4 — Чи викликає оновлення версії моделі поведінковий diff?

**Добре:** набір тестів безпеки (evals) як обов'язковий крок у CI між імпортом та просуванням моделі; diff порівнюється і переглядається так само, як diff коду.
**Верифікація:** конфігураційний файл CI. Якщо людина може просунути модель без тестування, контроль є Налаштованим, а не Примусовим.

### P5 — Чи розглядається пам'ять агента як вхідна поверхня?

**Добре:** записи в пам'ять або сховище RAG можна віднести до джерела; можливе масове видалення записів за джерелом.
**Верифікація:** простежте один запис у пам'яті до його джерела. Якщо сховище не може відповісти на питання "звідки це взялося", воно не зможе відповісти на питання "що ще звідти прийшло" в день, коли це матиме значення.
