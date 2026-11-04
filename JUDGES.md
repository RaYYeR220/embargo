# Review in five minutes

The fastest path to seeing every claim for yourself.

## 1. Switch is load-bearing — take it out and the project stops working

The embargo is not enforced by asking an agent to be careful. It is enforced by
Switch, in the path every message goes through. The guard
(`guard/app.py`) answers Switch's guardrails contract; Switch calls it before
each send and refuses a blocked one.

```
python scripts/validate_hook.py
```
Registers an agent, puts a case under embargo whose allowed rooms do **not**
include a public room, and has the agent try to post the case's material there.
Expected: `secret post refused by Switch: HTTP 422` and `RESULT: ENFORCED`.
Remove Switch and there is nothing to refuse the send — the guarantee is Switch's.

## 2. The headline number — grounding beats trusting the text

```
python bench/run.py
```
Writes `bench/results/triage.json`. Expected: the grounded desk accepts **14%**
of invalid reports vs the text baseline's **85%**, at **100%** recall on real
reports, saving ~**26 hours** of maintainer review the baseline saves none of.
The corpus is real public curl reports; the negative control is 89
patched-version claims that must be caught.

## 3. The whole desk, end to end

With a Switch stack running and seeded (see README → Run it):
```
python scripts/demo_flow.py
```
Walks report → grounded → private case → sandbox reproduction → advisory drafted
and **held** under embargo → human sign-off → embargo lifted → published, and
asserts the material cannot leak into the public room until disclosure.

## 4. No verdict without a run

```
python sandbox/probe.py 8.11.0 --parallel-max --no-such-option
```
Runs the real published curl 8.11.0 image: the real option is present, the
invented one is `ABSENT`. This is how the desk disproves a report that cites a
version or option that does not exist — without touching a vulnerability.

## Where to look

- `guard/app.py` — the embargo guard (Switch guardrails contract + case registry).
- `desk/agents/intake.py` — grounds a report, opens a private case, sets its embargo.
- `desk/agents/reproducer.py` + `sandbox/probe.py` — runs the named version.
- `desk/agents/disclosure.py` — drafts, holds, and publishes only after sign-off.
- `desk/verifier.py` — the grounding check.
- `CLAIMS.md` / `MOCKS.md` — every claim's evidence, and the real-vs-simulated line.
