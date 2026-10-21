# Agent Platform Security Assessment

An eighteen-check, evidence-tiered security assessment for AI agent platforms and landing zones on GCP.

Companion to the *Security as Code: AI Agent Security* series at [d3ep0ps.com](https://d3ep0ps.com):
- [The Agent Platform Security Assessment](https://d3ep0ps.com/#agent-platform-security-assessment) — the scoring framework and baseline checks (`R1`–`R6`, `I1`–`I6`, `P1`–`P5`)
- [The AI Gateway — Where Agent Security Policy Becomes Enforcement](https://d3ep0ps.com/#ai-gateway-enforcement) — moving checks from *Documented* to *Enforced* in the traffic path + the Gateway Bypass Test
- [The AI Landing Zone — The Floor Under Every Agent on GCP](https://d3ep0ps.com/#ai-landing-zone-gcp) — org policies, VPC-SC perimeters, per-agent SPIFFE identities, IAM ancestry verification, and check `R7`

Ukrainian version: [`README.ua.md`](README.ua.md) · [`assessment.ua.md`](assessment.ua.md) · [`scoring-sheet.ua.csv`](scoring-sheet.ua.csv)

## The method

Three boundaries, scored against three evidence tiers:

| Tier | Meaning |
|---|---|
| **Documented** | The control exists in a policy, architecture diagram, or wiki |
| **Configured** | The control exists in live configuration — you can produce command output for it today, but nothing stops a workload from working around it |
| **Enforced** | Working around the control fails a deployment, a CI pipeline, or a network/IAM connection |

**The rule:** an answer counts only at the tier you can produce evidence for, on demand.
Answer every check with a link to code, a negative CI test, or a command output — never with a meeting.

## The three boundaries

| Boundary | Question | Checks | OWASP ASI risks |
|---|---|---|---|
| **Reach** | What can the agent touch or mutate when it's tricked, and does it respect resource and token limits? | `R1`–`R7` | ASI01, ASI02, ASI05, ASI08, ASI09 |
| **Identity** | Who can talk to the agent, as whom does it act, and are logs tamper-proof? | `I1`–`I6` | ASI03, ASI07, ASI10 |
| **Provenance** | Where did the model and tools come from — would you notice an unapproved swap or poisoned memory? | `P1`–`P5` | ASI04, ASI06 |

## How to run it

1. Open [`assessment.md`](assessment.md) — each check has *what to ask*, *what good looks like*, and a *verify* command.
2. Run the **Gateway & Landing Zone Bypass Test** (at the bottom of [`assessment.md`](assessment.md)). Any gateway-backed check (`R5`, `R6`, `I3`, `I4`, `I5`, `I6`) whose gateway fails the bypass test is **Configured**, not **Enforced**.
3. Record results in [`scoring-sheet.csv`](scoring-sheet.csv) — one row per check: tier reached + link to evidence.
4. Score each boundary 0–3 (see below). Report the result as three digits: **Reach / Identity / Provenance**.
5. Commit the filled sheet to your platform repo. Re-run quarterly; the diff is your drift report.

## Scoring

| Score | Meaning |
|---|---|
| 0 | One or more checks fail outright (default SA, exported key, no sandbox, unauthenticated MCP tool) |
| 1 | Checks pass at Documented tier only |
| 2 | Most checks Configured — command output produced today |
| 3 | Controls Enforced — bypass fails a deployment, pipeline gate, or network/IAM probe |

A perfect 3/3/3 verifies facts about artifacts, identities, network perimeters, and platform guardrails.
The attacks live in behavior — see the closing section of the companion articles for what
this assessment deliberately does not claim to cover.

## License

CC BY-SA 4.0. Use it, adapt it, keep the attribution.

---

*Maintained by [Vitaliy Zhhuta](https://linkedin.com/in/vitaliyzhhuta) — [d3ep0ps.com](https://d3ep0ps.com).
If you want a second pair of eyes on your scores, get in touch.*
