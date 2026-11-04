# Embargo

A security-report desk for the people and AI agents who keep software safe — built on [Switch](https://github.com/sandbox-quantum/switch).

Maintainers of widely-used projects now receive far more vulnerability reports than a human can read. Most are not real. Each one still has to be looked at, and the ones that *are* real have to be handled under embargo, where a leak is its own kind of harm.

Embargo turns a team chat into the desk that handles that flow: reports arrive in a room, each claim is checked by actually running it rather than trusting the write-up, a private room per accepted case carries the fix to a human sign-off, and the whole thing publishes an advisory only when it is allowed to. The embargo itself is enforced inside Switch's own message path — material for a case cannot be sent into a room that case does not belong in.

Status: work in progress.
