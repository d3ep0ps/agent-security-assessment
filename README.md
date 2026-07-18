# Agent Platform Security Assessment

A seventeen-check, evidence-tiered security assessment for AI agent platforms on GCP.
Companion to the article ["The Agent Platform Security Assessment"](https://d3ep0ps.com/#agent-platform-security-assessment) and
the *Security as Code: AI Agent Security* series at [d3ep0ps.com](https://d3ep0ps.com).

## The method

Three boundaries, scored against three evidence tiers:

| Tier | Meaning |
|---|---|
| **Documented** | The control exists in a policy or wiki |
| **Configured** | The control exists in live configuration — you can produce command output for it today |
| **Enforced** | Bypassing the control requires changing code or failing a deployment |

**The rule:** an answer counts only at the tier you can produce evidence for, on demand.
Answer every check with a link to code or a command output — never with a meeting.

## The three boundaries

| Boundary | Question | OWASP ASI risks |
|---|---|---|
| **Reach** | What can the agent touch when it's tricked, and does it respect resource limits? | ASI01, ASI02, ASI05, ASI08 |
| **Identity** | Who can talk to the agent, as whom does it act, and are logs tamper-proof? | ASI03, ASI07, ASI10 |
| **Provenance** | Where did the model come from — would you notice a swap? | ASI04, ASI06 |

## How to run it

1. Open [`assessment.md`](assessment.md) — each check has *what to ask*, *what good looks like*, and a *verify* command.
2. Record results in [`scoring-sheet.csv`](scoring-sheet.csv) — one row per check: tier reached + link to evidence.
3. Score each boundary 0–3 (see below). Report the result as three digits: **Reach / Identity / Provenance**.
4. Commit the filled sheet to your platform repo. Re-run quarterly; the diff is your drift report.

## Scoring

| Score | Meaning |
|---|---|
| 0 | One or more checks fail outright (default SA, exported key, no sandbox) |
| 1 | Checks pass at Documented tier only |
| 2 | Most checks Configured — command output produced today |
| 3 | Controls Enforced — bypass requires a code change or a failed deploy |

A perfect 3/3/3 verifies facts about artifacts, identities, and configuration.
The attacks live in behavior — see the closing section of the article for what
this assessment deliberately does not claim to cover.

## License

CC BY-SA 4.0. Use it, adapt it, keep the attribution.

---

*Maintained by [Vitaliy Zhhuta](https://linkedin.com/in/vitaliyzhhuta) — [d3ep0ps.com](https://d3ep0ps.com).
If you want a second pair of eyes on your scores, get in touch.*
