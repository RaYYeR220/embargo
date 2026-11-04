# Real vs simulated

Where the line is, drawn plainly.

## Real

- **Switch.** A self-hosted Switch 0.31.0 stack from Switch's own published
  compose. The rooms, agents, roles, the agent protocol and the guardrails hook
  are all the real thing, not a stand-in.
- **The embargo guard.** A real service on Switch's guardrails contract. Switch
  really calls it before every send and really refuses a blocked message.
- **The corpus.** Every entry is a real, public curl report: the real CVEs come
  from curl's own OSV feed (`curl.se/docs/vuln.json`), and the invalid ones from
  the curl maintainer's own published list of reports that were submitted as
  vulnerabilities and were not. No report was invented or hand-labelled.
- **The grounding check.** Runs against the real advisory data, offline and
  deterministic.
- **The sandbox probe.** Runs the real, published `curlimages/curl:<version>`
  image and reads back what it actually reports.

## Simulated / limited, and why

- **The reproducer is a benign probe, not an exploit.** It confirms whether the
  named release and the cited options exist and what the binary reports about
  itself. It does **not** trigger a vulnerability. A real desk would hand a
  memory-safety case to a human or a sandboxed harness for a full reproduction;
  our reproducer establishes the ground truth that disproves most invalid
  reports (a release or option that does not exist) and prepares the
  environment, and a richer coding agent can take it further through Switch.
- **Severity is an estimate.** The disclosure agent gives a clearly-labelled
  estimated severity from the bug class, as a starting point for the human to
  confirm — not a computed CVSS 4.0 vector.
- **The embargo secrets are the report's title and proof lines.** The guard
  blocks messages that carry those strings outside the case's rooms. It matches
  on the material as written; a deliberate paraphrase to evade it is out of
  scope for this version, and is noted as a limit rather than hidden.
- **Fail-open on a guard outage.** Switch's global guardrails policy fails open
  if the guard is unreachable (a message goes unchecked rather than all
  messaging stopping). Within a reachable guard the decision is fail-closed —
  anything it cannot clear, it blocks. We run the guard beside the server to
  keep the unreachable case rare, and say so rather than implying the guard can
  never be bypassed.
