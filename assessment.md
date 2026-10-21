# The Eighteen Checks

Format per check: **Ask → What good looks like → Verify.**
Evidence rule: an answer counts only at the tier you can prove on demand.

---

## Boundary 1 — Reach (ASI01, ASI02, ASI05, ASI08, ASI09)

### R1 — Does any agent run as a default service account?

**Good:** every agent workload has a dedicated identity (IAM agent identity or dedicated per-agent SA); no basic roles (`Owner`/`Editor`/`Viewer`).

```bash
gcloud projects get-iam-policy $PROJECT \
  --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members)" \
  --filter="bindings.members:compute@developer.gserviceaccount.com"
```

Any `roles/editor` row is a finding.

### R2 — Is the agent's IAM scoped to resources, not the project or folder hierarchy?

**Good:** agents, MCP tools, and data live in separate projects; grants are bound at dataset/bucket/secret/sub-agent level (`aiplatform.reasoningEngines.query`); agent identities have zero broad project or inherited folder/group roles.

```bash
# 1. Direct project policy check (expect: empty)
gcloud projects get-iam-policy $PROJECT \
  --flatten="bindings[].members" \
  --filter="bindings.members:$AGENT_PRINCIPAL"

# 2. Landing Zone Enforced check: analyze effective IAM across folder/org ancestry
#    and group expansion to ensure the agent cannot inherit broad data or model roles
gcloud asset analyze-iam-policy \
  --organization=$ORG_ID \
  --identity="$AGENT_PRINCIPAL" \
  --expand-groups \
  --format="table(ACLs.resource, ACLs.role)"

# 3. Check for overly broad fleet bindings (principalSet://) on the agent trust domain
gcloud asset search-all-iam-policies \
  --scope="organizations/$ORG_ID" \
  --query="policy:agents.global.org-${ORG_ID}.system.id.goog"
```

### R3 — Is Workload Identity on for every node pool?

**Good:** every pool reports `GKE_METADATA`. Autopilot passes by construction (Enforced).

```bash
gcloud container node-pools list --cluster=$CLUSTER --region=$REGION \
  --format="table(name, config.workloadMetadataConfig.mode)"
```

### R4 — Does agent-generated code run in a sandbox with default-deny egress?

**Good:** gVisor-isolated execution (GKE Agent Sandbox or equivalent); allowed destinations enumerated in the `SandboxTemplate`; default-deny egress except via the AI gateway or Secure Web Proxy.

```bash
kubectl get pods -n $AGENT_NS \
  -o custom-columns="NAME:.metadata.name,RUNTIME:.spec.runtimeClassName"
```

### R5 — Is prompt and tool-call screening a floor, or a choice?

**Good:** Model Armor floor settings enforced at organization/folder/project level and wired into the AI gateway (ingress user prompts + egress tool calls, tool responses, and A2A messages) with fail-closed behavior on unparseable content types.

```bash
gcloud model-armor floorsettings describe \
  --full-uri="organizations/$ORG_ID/locations/global/floorSetting"

gcloud model-armor floorsettings describe \
  --full-uri="projects/$PROJECT/locations/global/floorSetting"
```

### R6 — Does the platform enforce runaway execution and token consumption limits?

**Good:** hard timeout and step count limits in the runtime (e.g., Vertex AI Reasoning Engine `maxSteps`), container CPU/Memory limits, **per-agent token ceilings enforced in the traffic path at the AI gateway** (keyed to verified agent identity, never a client-supplied header), and project spend-cap budgets as a circuit breaker.

```bash
# 1. Check GKE resource limits for agent execution namespace
kubectl get limitrange -n $AGENT_NS -o yaml

# 2. Check Vertex AI Reasoning Engine step/validation schemas
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${LOCATION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines" \
  | jq -r '.reasoningEngines[].spec.templates[] | select(.validationSchema != null)'

# 3. Verify gateway token rate-limit policy (e.g., Agent Router / Envoy BackendTrafficPolicy or Apigee LLMTokenQuota)
kubectl get backendtrafficpolicy -A -o yaml | grep -A 15 "rateLimit:"
```

### R7 — Do state-changing tools require human confirmation, and are read-only tools unable to write? (OWASP ASI09)

**Good:** a developer boolean (`readOnlyHint: True`) cannot silently remove human oversight from a tool that mutates state. Enforced when all four hold:
1. CI rejects any MCP tool without `readOnlyHint: true` that does not declare `destructiveHint: true`.
2. Any change to `readOnlyHint` requires Agent Registry re-approval.
3. Read-only and write tools run as separate MCP services with separate identities; the read-only identity holds reader IAM roles only, so a mislabelled write fails at the data layer.
4. A red-team test confirms that every write-capable tool prompts the user for confirmation.

```bash
# 1. Verify read-only MCP service identity holds zero write/admin roles across the data project
gcloud asset analyze-iam-policy \
  --scope="projects/$DATA_PROJECT" \
  --identity="serviceAccount:$MCP_READONLY_SA" \
  --format="table(ACLs.resource, ACLs.role)" | grep -Ev "reader|viewer|metadataViewer"

# 2. Scan MCP tool definitions in repo for missing destructiveHint when readOnlyHint is not true
grep -rn "@mcp.tool" .
```

---

## Boundary 2 — Identity & Access (ASI03, ASI07, ASI10)

### I1 — Can you list every agent identity on the platform?

**Good:** one identity per agent, named to a convention, enumerable in one command.
Strongest model: [IAM agent identity](https://docs.cloud.google.com/iam/docs/agent-identity-overview)
(`principal://agents.global.org-ORG_ID.system.id.goog/...` — per-agent SPIFFE principal, lifecycle-tied, mTLS + DPoP certificate-bound tokens) on Agent Platform runtime, Gemini Enterprise, and Cloud Run; dedicated per-agent Google SA via Workload Identity Federation on GKE.

```bash
# Service-account-based agents (GKE WIF)
gcloud iam service-accounts list \
  --filter="displayName:agent" --format="table(email, displayName)"

# Agent Platform runtime: which identity each agent actually has
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${LOCATION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines" \
  | jq -r '.reasoningEngines[] | [.displayName, .spec.effectiveIdentity] | @tsv'
```

An `effectiveIdentity` showing an SA email on a managed runtime = agent predates or opted out of native IAM agent identity.

### I2 — Do any agent service accounts have exported keys?

**Good:** silence. Agents on IAM agent identity pass by construction (no exportable keys; certificate-bound tokens, un-replayable outside the runtime) — Enforced tier.
Then check nobody opted out of the Context-Aware Access binding:

```bash
grep -rn "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES" .
```

Any occurrence set to `False` is a finding.

```bash
for sa in $(gcloud iam service-accounts list --format="value(email)" --filter="displayName:agent"); do
  gcloud iam service-accounts keys list --iam-account=$sa \
    --managed-by=user --format="value(name)" | grep -q . && echo "KEY FOUND: $sa"
done
```

For the Enforced tier, verify that managed key creation and upload org policies are strictly enforced:

```bash
for constraint in \
  iam.managed.disableServiceAccountKeyCreation \
  iam.managed.disableServiceAccountKeyUpload \
  iam.disableServiceAccountKeyCreation; do
  gcloud org-policies describe $constraint --project=$PROJECT --effective
done
```

### I3 — Is agent-auth separated from user-auth?

**Good:** tools touching user data require a delegated user credential (OAuth token) in the call path alongside the agent/service identity (`X-Serverless-Authorization` on default `*.run.app` URLs); the agent's own identity cannot read user-scoped data alone.
**Verify:** code and gateway policy check — link the tool and gateway implementations. Evidence is the code and negative test, not a diagram.

### I4 — Do your agents verify who they're talking to?

**Good:** inter-agent traffic on mTLS / DPoP via Agent Gateway or mesh; A2A endpoints reject unsigned `AgentCard` payloads or cards signed outside the corporate root of trust; parent-to-sub-agent delegation uses narrow `aiplatform.reasoningEngines.query` bindings per target agent, never project-wide `roles/aiplatform.user`.
**Verify:** attempt an unauthenticated or unsigned card exchange against a production A2A endpoint from outside the gateway. It must fail before task delegation.

### I5 — Is there an enforced inventory of MCP servers, with owners?

**Good:** private Agent Registry (or API hub / GitOps-reviewed gateway backend list) of every MCP endpoint with an owner; `run.managed.requireInvokerIam` enforced org-wide (no `allUsers`); `discoveryengine.managed.disableCustomMcpServerConnector` enforced at org level and only relaxed in the dedicated Gemini Enterprise hub project alongside `allowedDataSources` and `allowedEgressFqdns`.

```bash
gcloud org-policies describe run.managed.requireInvokerIam --project=$MCP_PROJECT --effective
gcloud org-policies describe discoveryengine.managed.disableCustomMcpServerConnector --organization=$ORG_ID
```

**Verify:** pick an MCP endpoint or FQDN NOT on the allowlist; confirm an agent cannot reach it.

### I6 — Are execution and tool-call audit logs tamper-proof?

**Good:** all agent prompts, intermediate thoughts, tool calls, and A2A messages are written by the gateway/platform (outside the agent's container reach) to a locked, immutable log bucket in the dedicated Security logging project (`prj-sec-logging`) with a Retention Policy Lock. Even project Owners cannot delete these logs during the retention window.

```bash
gcloud logging buckets describe $BUCKET_ID --location=$LOCATION --project=$SEC_LOGGING_PROJECT \
  --format="table(name, retentionDays, locked)"
```

Passing result at Enforced tier: `locked: true` and `retentionDays > 0`.

---

## Boundary 3 — Provenance (ASI04, ASI06)

### P1 — Are model versions pinned by digest or immutable GA ID (and governed by an org allowlist)?

**Good:** no `-latest` or `-preview` aliases in production manifests; `vertexai.allowedModels` org policy enforced on the production folder allowing `:predict` only on approved GA models (no `:tune`, no `:deploy`), reviewed monthly against the model retirement schedule.

```bash
gcloud org-policies describe vertexai.allowedModels --folder=$PROD_AI_FOLDER_ID
```

**Verify:** grep deployment manifests and inspect the active `vertexai.allowedModels` policy.

### P2 — Is there one path to production for models and Cloud Run services?

**Good:** serving loads from one attested registry; write access held only by the pipeline SA; `run.managed.disableInlinedSource` enforced so nobody can deploy Cloud Run services from unreviewed local source uploads.

```bash
gcloud storage buckets get-iam-policy gs://$MODEL_BUCKET \
  --format="table(bindings.role, bindings.members)"

gcloud org-policies describe run.managed.disableInlinedSource --project=$PROJECT --effective
```

Humans with `objectAdmin` are alternate paths to production.

### P3 — Is the serving container attested?

**Good:** Binary Authorization in `ENFORCED_BLOCK_AND_AUDIT_LOG` on GKE and enforced on Cloud Run via `run.allowedBinaryAuthorizationPolicies`.

```bash
gcloud container binauthz policy export
gcloud org-policies describe run.allowedBinaryAuthorizationPolicies --folder=$AI_WORKLOADS_FOLDER_ID
```

### P4 — Does a model version bump trigger a behavioral diff?

**Good:** safety/security regression eval suite as a *required* CI gate in staging before any successor model ID is added to the production `vertexai.allowedModels` policy; diffs reviewed like code diffs.
**Verify:** the CI config file. If a human can promote without the eval passing, it's Configured, not Enforced.

### P5 — Is agent memory treated as an input surface (and CMEK-protected)?

**Good:** memory/RAG writes attributable to a source; bulk expiry by source is possible; grounding restricted via `vertexai.genAIGroundingSources` and `vertexai.disableGenAIGoogleSearchGrounding` in production; Memory Bank / Sessions / Vector Search encrypted with CMEK (`gcp.restrictNonCmekServices`) on regional/multi-regional endpoints.
**Verify:** trace one memory entry to its origin and verify `gcp.restrictNonCmekServices` on the data project.

---

## The Gateway & Landing Zone Bypass Test

A gateway or landing zone diagram is **Configured**. Gateway-backed controls (`R5`, `R6`, `I3`, `I4`, `I5`, `I6`) only count as **Enforced** if the agent runtime cannot bypass the enforcement path. Run these probes against every production agent workload; if any probe fails, downgrade the dependent checks to **Configured**.

### 1. No direct internet or provider egress
- **On GKE / Cloud Run:** default-deny `NetworkPolicy` and VPC firewall rules block everything except the AI gateway / Secure Web Proxy; `run.allowedVPCEgress = all-traffic` forces Cloud Run traffic into the VPC.
- **On Agent Platform managed runtime:** the runtime project **must** sit inside an enforced **VPC Service Controls** perimeter (`aiplatform.googleapis.com`, `discoveryengine.googleapis.com`, `modelarmor.googleapis.com`, etc.) with Private Service Connect interfaces (PSC-I) routing egress through Secure Web Proxy. Outside a VPC-SC perimeter, managed runtimes reach the internet directly from Google's tenant network, bypassing your VPC firewall completely.

```bash
# GKE probe: direct provider call from inside the agent pod must time out (not return an HTTP status)
kubectl exec -n $AGENT_NS deploy/$AGENT -- curl -sS -m 5 -o /dev/null -w '%{http_code}\n' \
  https://generativelanguage.googleapis.com/

# Managed runtime & Cloud Run check: verify VPC-SC perimeter enforces aiplatform & run in prod
gcloud access-context-manager perimeters describe $PROD_PERIMETER \
  --policy=$ACCESS_POLICY_ID --format="yaml(status.restrictedServices, status.resources)"
```

### 2. The gateway holds the credentials — and the agent has no inherited IAM path to models
An agent with no direct project role can still inherit `aiplatform.endpoints.predict` from a folder, a Google Group, or a `principalSet://` fleet binding on the trust domain.

```bash
# 2a. No provider or tool secrets in the agent container environment
kubectl exec -n $AGENT_NS deploy/$AGENT -- env | grep -Ei 'api[_-]?key|secret|password|token'

# 2b. Full IAM ancestry + group expansion check via Cloud Asset Inventory (expect: zero direct model predict grants to the agent identity; only the gateway SA may call the model)
gcloud asset analyze-iam-policy \
  --organization=$ORG_ID \
  --identity="$AGENT_PRINCIPAL" \
  --permissions="aiplatform.endpoints.predict" \
  --expand-groups
```

### 3. The agent cannot mutate gateway or guardrail policy (and screening fails closed)

```bash
# Agent identity cannot modify gateway routing or RBAC policies
kubectl auth can-i update agentgatewaypolicies.agentgateway.dev \
  -n agentgateway-system --as=system:serviceaccount:$AGENT_NS:$AGENT_KSA   # expect: no
```
