# Claims ledger

Every claim this project makes, with the evidence tier and how to reproduce it.
Tiers: **REPRODUCIBLE** (run the script yourself), **VERIFIED-LIVE** (observed
against a running Switch during the build), **MODELED** (a figure derived from a
stated assumption), **NOT-CLAIMED** (what we are careful *not* to say).

## REPRODUCIBLE

- **The embargo is enforced inside Switch's own send path, not by prompting an
  agent.** The guard answers Switch's guardrails contract; Switch calls it
  before every message and refuses the send on a block.
  → `scripts/validate_hook.py` opens an agent, puts a case under embargo, and
  has the agent try to post the case's material into a room outside the case.
  The send is refused (HTTP 422) and the material never lands.

- **Grounded triage beats trusting the write-up, measured.** Over a 227-item
  corpus, the grounded desk accepts 14% of invalid reports; a baseline that
  trusts the text accepts 85%. The desk keeps 100% of real reports (recall);
  the baseline keeps 83%.
  → `python bench/run.py` writes `bench/results/triage.json`. Numbers in this
  repo are read from that file, not typed by hand.

- **The desk saves maintainer review time the baseline does not.** On the same
  corpus the desk auto-dispositions 53 invalid reports and escalates 65 more to
  a human rather than auto-accepting them; at the curl maintainer's own figure
  of 30 minutes per report, that is ~26 hours of review the baseline saves none
  of. → `bench/results/triage.json` → `desk_grounded.maintainer_minutes_saved`.

- **A claimed version or option that does not exist is caught by running the
  real binary.** → `python sandbox/probe.py 8.11.0 --parallel-max --no-such-option`
  reports the version banner, the present option, and the absent one. Requires
  Docker.

- **The whole desk runs end to end: report → grounded → private case → sandbox
  reproduction → draft held under embargo → human sign-off → published.**
  → `python scripts/demo_flow.py` against a running Switch asserts each step,
  including that the material cannot leak into the public room until disclosure.

## VERIFIED-LIVE

- The desk runs on a self-hosted Switch 0.31.0 stack brought up from Switch's
  own published compose (switch-core + Mattermost + gateway). Observed: the
  guard registered as the Trust provider (`enabled: true`), the agents
  registered over the agent protocol, the rooms created, and a blocked send
  posting a "blocked by Switch Trust" notice in place of the message.

## MODELED

- **~26 hours / 1590 minutes saved** uses 30 minutes per report, which is the
  figure the curl maintainer gives publicly for the human cost of one report.
  The minute total is `auto-dispositioned invalid reports × 30`. It measures
  reports a human did not have to open on this corpus; it is not a claim about
  any one project's live inbox.

## NOT-CLAIMED

- We do **not** claim to find new vulnerabilities, write exploits, or reproduce
  memory-corruption bugs. The reproducer runs **benign** capability checks on a
  published binary (version, features, option presence); it does not exercise a
  vulnerability. See `MOCKS.md`.
- We do **not** claim the grounded check replaces human review. It auto-rejects
  the clearly-ungrounded, escalates the uncertain, and never auto-accepts a
  report as real — a human still confirms every real case.
- We do **not** claim perfect precision. The desk accepts 20 of 138 invalid
  items (14%) on the corpus; those are listed as the honest limit in
  `bench/results/triage.json` and discussed in the README.
