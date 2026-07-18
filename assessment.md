# The Seventeen Checks

Format per check: **Ask → What good looks like → Verify.**
Evidence rule: an answer counts only at the tier you can prove on demand.

---

## Boundary 1 — Reach (ASI01, ASI02, ASI05, ASI08)

### R1 — Does any agent run as a default service account?

**Good:** every agent workload has a dedicated SA; no basic roles (Owner/Editor/Viewer).

```bash
gcloud projects get-iam-policy $PROJECT \
  --flatten="bindings[].members" \
  --format="table(bindings.role, bindings.members)" \
  --filter="bindings.members:compute@developer.gserviceaccount.com"
```

Any `roles/editor` row is a finding.

### R2 — Is the agent's IAM scoped to resources, not the project?

**Good:** grants at dataset/bucket/secret level; agent SAs absent from project-level policy.

```bash
gcloud projects get-iam-policy $PROJECT \
  --flatten="bindings[].members" \
  --filter="bindings.members:$AGENT_SA"
```

Passing result at project level: empty.

### R3 — Is Workload Identity on for every node pool?

**Good:** every pool reports `GKE_METADATA`. Autopilot passes by construction (Enforced).

```bash
gcloud container node-pools list --cluster=$CLUSTER --region=$REGION \
  --format="table(name, config.workloadMetadataConfig.mode)"
```

### R4 — Does agent-generated code run in a sandbox with default-deny egress?

**Good:** gVisor-isolated execution (GKE Agent Sandbox or equivalent); allowed
destinations enumerated in the `SandboxTemplate`.

```bash
kubectl get pods -n $AGENT_NS \
  -o custom-columns="NAME:.metadata.name,RUNTIME:.spec.runtimeClassName"
```

### R5 — Is prompt screening a floor, or a choice?

**Good:** Model Armor floor settings at org/project level — a minimum no team can opt out of.

```bash
gcloud model-armor floorsettings describe \
  --full-uri="projects/$PROJECT/locations/global/floorSetting"
```

### R6 — Does the platform enforce runaway execution and token consumption limits?

**Good:** Hard timeout limits on execution, maximum step count limits (e.g., Vertex AI Reasoning Engine `maxSteps`), and container CPU/Memory limits, preventing denial of service, resource exhaustion, or runaway API costs.

```bash
# Check GKE resource limits for agent execution namespace
kubectl get limitrange -n $AGENT_NS -o yaml

# Check Vertex AI Reasoning Engine step/validation schemas
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${LOCATION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines" \
  | jq -r '.reasoningEngines[].spec.templates[] | select(.validationSchema != null)'
```

---

## Boundary 2 — Identity & Access (ASI03, ASI07, ASI10)

### I1 — Can you list every agent identity on the platform?

**Good:** one identity per agent, named to a convention, enumerable in one command.
Strongest model: [IAM agent identity](https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/runtime/agent-identity)
(per-agent SPIFFE principal, lifecycle-tied) rather than service accounts.

```bash
# Service-account-based agents
gcloud iam service-accounts list \
  --filter="displayName:agent" --format="table(email, displayName)"

# Agent Runtime: which identity each agent actually has
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://${LOCATION}-aiplatform.googleapis.com/v1beta1/projects/${PROJECT}/locations/${LOCATION}/reasoningEngines" \
  | jq -r '.reasoningEngines[] | [.displayName, .spec.effectiveIdentity] | @tsv'
```

An `effectiveIdentity` showing an SA email = agent predates or opted out of agent identity.

### I2 — Do any agent service accounts have exported keys?

**Good:** silence. Agents on IAM agent identity pass by construction (no exportable
keys; certificate-bound tokens, un-replayable outside the runtime) — Enforced tier.
Then check nobody opted out of the CAA binding:

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

For the Enforced tier, verify that key creation org policies are strictly active:
```bash
gcloud resource-manager org-policies describe iam.disableServiceAccountKeyCreation \
  --project=$PROJECT --effective
```

### I3 — Is agent-auth separated from user-auth?

**Good:** tools touching user data require a delegated user credential in the call
path; the agent's own SA cannot read user-scoped data alone.
**Verify:** code check — link the tool implementations. Evidence is the code, not a diagram.

### I4 — Do your agents verify who they're talking to?

**Good:** inter-agent traffic on mTLS (mesh or Agent Gateway); A2A endpoints reject
unsigned/unauthenticated peers; no agent-to-agent path bypasses the gateway.
**Verify:** attempt an unauthenticated card exchange against a production A2A endpoint
from outside the mesh. It should fail at the transport layer.

### I5 — Is there an inventory of MCP servers, with owners?

**Good:** a registry (gateway registry or reviewed YAML in git) of every MCP endpoint,
each with an owner; egress rules block unlisted endpoints.
**Verify:** pick an endpoint NOT on the list; confirm an agent pod cannot reach it.

### I6 — Are execution and tool-call audit logs tamper-proof?

**Good:** all agent prompts, intermediate thoughts, tool calls, and responses are written directly to a locked, immutable log bucket with a Retention Policy Lock. Even project Owners cannot delete these logs during the retention window.

```bash
gcloud logging buckets describe $BUCKET_ID --location=$LOCATION --project=$PROJECT \
  --format="table(name, retentionDays, locked)"
```

Passing result at Enforced tier: `locked: true` and `retentionDays > 0`.

---

## Boundary 3 — Provenance (ASI04, ASI06)

### P1 — Are model versions pinned by digest?

**Good:** no `latest` tags in model references; updates are ingestion events.
**Verify:** grep deployment manifests and registry references. Evidence is the manifest in git.

### P2 — Is there one path to production for models?

**Good:** serving loads from one registry; write access held only by the pipeline SA.

```bash
gcloud storage buckets get-iam-policy gs://$MODEL_BUCKET \
  --format="table(bindings.role, bindings.members)"
```

Humans with `objectAdmin` are alternate paths to production.

### P3 — Is the serving container attested?

**Good:** Binary Authorization in `ENFORCED_BLOCK_AND_AUDIT_LOG` on the serving cluster.

```bash
gcloud container binauthz policy export
```

### P4 — Does a model version bump trigger a behavioral diff?

**Good:** safety/security eval suite as a *required* CI step between ingestion and
promotion; diffs reviewed like code diffs.
**Verify:** the CI config file. If a human can promote without the eval, it's Configured, not Enforced.

### P5 — Is agent memory treated as an input surface?

**Good:** memory/RAG writes attributable to a source; bulk expiry by source is possible.
**Verify:** trace one memory entry to its origin. If the store can't answer "where did
this come from," it can't answer "what else came from there."
