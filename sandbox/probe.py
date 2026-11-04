"""Benign capability probes against a pinned curl version, in a container.

A large share of invalid reports cite a version, an option or a build feature
that the named release does not actually have. The cheapest way to see that is
to run the real binary and ask it — no exploit, just the version banner and the
feature/option list the release ships.

The probe runs the official, published ``curlimages/curl:<version>`` image and
reads back:
  * whether that version image exists at all,
  * its ``--version`` banner (version, libraries, features),
  * whether a named command-line option exists in that release.

Nothing here sends traffic to a target or exercises a vulnerability; it only
reads what the release declares about itself. Requires Docker.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field

_VERSION_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_OPTION_RE = re.compile(r"^--[a-z0-9][a-z0-9-]*$")


@dataclass
class ProbeResult:
    version: str
    image_exists: bool
    version_banner: str | None = None
    features: list[str] = field(default_factory=list)
    option_checks: dict[str, bool] = field(default_factory=dict)
    error: str | None = None

    def summary(self) -> str:
        if not self.image_exists:
            return f"No published curl image for version {self.version} — the release named in the report could not be run."
        lines = [f"curl {self.version} ran. {self.version_banner or ''}".strip()]
        if self.features:
            lines.append("features: " + ", ".join(self.features))
        for opt, present in self.option_checks.items():
            lines.append(f"option {opt}: {'present' if present else 'ABSENT in this release'}")
        return "\n".join(lines)


def _run(args: list[str], timeout: int = 90) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, check=False
    )


def probe(version: str, options: list[str] | None = None) -> ProbeResult:
    """Run benign checks on ``curlimages/curl:<version>``.

    `version` must be a plain semver; `options` must be `--long-form` flags.
    Anything else is rejected rather than shelled out, so a report's text can
    never steer the command.
    """
    if not _VERSION_RE.match(version):
        return ProbeResult(version, False, error="version is not a plain release number")
    if shutil.which("docker") is None:
        return ProbeResult(version, False, error="docker is not available")

    options = [o for o in (options or []) if _OPTION_RE.match(o)]
    image = f"curlimages/curl:{version}"

    banner = _run(["docker", "run", "--rm", "--network", "none", image, "--version"])
    if banner.returncode != 0:
        # most often: the tag does not exist
        pull = _run(["docker", "pull", image], timeout=120)
        if pull.returncode != 0:
            return ProbeResult(version, False, error="image/tag not found")
        banner = _run(["docker", "run", "--rm", "--network", "none", image, "--version"])
        if banner.returncode != 0:
            return ProbeResult(version, False, error=banner.stderr.strip()[:200])

    banner_line = banner.stdout.strip().splitlines()[0] if banner.stdout.strip() else ""
    features = []
    for line in banner.stdout.splitlines():
        if line.lower().startswith("features:"):
            features = line.split(":", 1)[1].split()

    checks: dict[str, bool] = {}
    if options:
        helpout = _run(["docker", "run", "--rm", "--network", "none", image, "--help", "all"])
        text = helpout.stdout
        for opt in options:
            checks[opt] = opt in text

    return ProbeResult(
        version=version,
        image_exists=True,
        version_banner=banner_line,
        features=features,
        option_checks=checks,
    )


if __name__ == "__main__":
    import sys

    v = sys.argv[1] if len(sys.argv) > 1 else "8.11.0"
    opts = sys.argv[2:]
    print(probe(v, opts).summary())
