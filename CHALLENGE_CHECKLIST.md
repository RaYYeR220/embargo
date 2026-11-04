# How this is judged, and where the evidence is

The four things the judges weigh, each mapped to what proves it.

## Use of Switch — is it central, would the project stop working without it? (30%)

- The embargo is enforced by Switch's own guardrails hook, in the message path.
  Remove Switch and nothing refuses a leaking send. → `guard/app.py`,
  `scripts/validate_hook.py` (HTTP 422 block), `JUDGES.md` §1.
- The desk is rooms, agents, roles, links and the agent protocol — all Switch
  primitives. Reports arrive in a Switch room; each case is a private Switch
  room with a human-held exclusive role; disclosure crosses rooms only when
  allowed. → `desk/agents/intake.py` (`create_room`, roles, links),
  `deploy/switch/embargo-desk.template.yaml`.
- Agents of different kinds join over the agent protocol (our intake,
  disclosure and reproducer; a coding agent such as Claude Code can take the
  reproducer seat). → `desk/switch_client.py`.

## Technical execution — does it run, can someone clone and reproduce it? (25%)

- One corpus builder, one benchmark, one probe, one end-to-end flow, all
  runnable. → `bench/build_corpus.py`, `bench/run.py`, `sandbox/probe.py`,
  `scripts/demo_flow.py`.
- Numbers come from `bench/results/triage.json`, not from prose.
- The stack is Switch's own published compose at a pinned version (0.31.0); the
  guard and agents have Dockerfiles and a compose. → `README.md` → Run it,
  `deploy/desk-compose.yml`.

## Creativity and impact — a fresh idea, a problem a real team has (25%)

- The problem is this year's: maintainers of widely-used projects are flooded
  with vulnerability reports, most invalid, each still needing review, and the
  real ones needing embargo. The desk grounds the flood and protects the real
  cases. → `README.md` → Why.
- The corpus is a real maintainer's real inbox (curl's CVEs and the curl
  maintainer's own slop list), not a toy. → `bench/corpus/`.

## Presentation — do the demo and README show how Switch is used? (20%)

- `README.md` leads with the problem and the mechanism, with an architecture
  diagram and a one-command path to each proof.
- `JUDGES.md` is the five-minute reviewer path.
- `CLAIMS.md` and `MOCKS.md` state every claim's evidence and draw the
  real-vs-simulated line.
- The demo video walks the embargo being enforced live.
