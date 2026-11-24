# CI, testing and how it is maintained

Every pull request and every push to `main` runs the whole pipeline. The release runs it again
before publishing. A **nightly** run (01:23 UTC) repeats everything against that day's images
and feeds, with longer fuzzing and an OWASP ZAP scan of the panel. `main` is protected: all
jobs must pass, changes come through pull requests, and no force-push is allowed.

| Job | What it proves | When |
|---|---|---|
| Tests (Python 3.10, 3.12, 3.14) | unit tests of every part, plus fuzzing of every parser that reads outside data (`FUZZ_N` cases: 300 per push, 5000 at night) | every run |
| Lint, Bandit, secrets | ruff; Bandit at medium and above; gitleaks over the full history | every run |
| Fresh install, lifecycle | a clean Ubuntu install; install, upgrade, rollback, uninstall leave nothing behind | every run |
| Package | the wheel and sdist hold exactly what they should, install in a fresh virtualenv, and run | every run |
| Red team | real attacks on an isolated Docker network against a server installed from the built wheel ([red team](REDTEAM.md)) | every run; with the ZAP baseline at night |
| Clouds, databases | the off-site copy on emulated AWS, Google Cloud, Azure and Oracle stores; backup and restore of MariaDB and PostgreSQL | every run |
| Docs | links resolve; no em dash; no private names (from the `FORBIDDEN_TERMS` secret) | every run |
| Shell, units | shellcheck; `systemd-analyze verify` and the panel's sandbox score | every run |
| CodeQL | code scanning (security-extended) | every run and weekly |
| Dependabot | the pinned GitHub Actions weekly; security updates for Python build tools when an alert appears | weekly |

## The red team, and how it grows

The red team runs as `bash ci/redteam/run.sh`. Each attack records **PASS** (stopped or detected
as designed), **FAIL** (a defense did not hold: CI fails) or **GAP** (a known limitation,
reported and planned).

| Stage | Where | Attacks |
|---|---|---|
| SSH, web, host, network, backups, secrets | `run.sh` | brute force, probes and floods, persistence, miners, egress, backup theft and tampering, leaks |
| Panel in a real browser | `browser_attack.py` (Playwright) | sign-in with the mailed code, a hostile page in the same browser |
| Panel over raw HTTP and the root mailer | `panel_attack.py` | DNS rebinding, CSRF, XSS, SQL injection, session theft, code replay and guessing, a taken-over panel abusing root |
| Approvals by mail reply | `approvals_attack.py` (a real IMAP server over TLS) | forged senders, a planted verdict, another mail server's verdict, a non-admin, commands instead of an action line, quoted codes, replays, a one-admin reboot, SSRF through a source |
| OWASP ZAP baseline | `run.sh` with `ZAP=1` (nightly) | ZAP's passive rules on the panel |
| The pip package | `run.sh` | tampered or planted files, dependencies, startup code, write access |

**Adding an attack.** Every new feature that takes outside input or changes the server comes
with:

1. **Unit tests for its refusals.** Every way it must say no gets its own test.
2. **A fuzz test** if it parses anything from outside (`guard/tests/test_fuzz.py`).
3. **A red-team check** that attacks the installed system the way an attacker would. Give it
   an ID by phase, a MITRE ATT&CK technique, the attack, the expected defense, and the
   evidence.

A check is a GAP only when the limitation is understood and on the roadmap. Anything else is a
FAIL.

**Checklists and outside tools.** Public red-team skill collections were reviewed for this
suite. Most entries are written for interactive engagements, other stacks (Active Directory,
smart contracts, binaries), or a paid service, and none fit an unattended CI run as they are.
The suite takes the ideas, not the code:
- authorization and tenant isolation became the panel's role checks;
- KEV matching became the advisories;
- secret scanning was already a CI job.

Outside code joins CI only when it meets three rules:
1. It is pinned by digest or exact version.
2. It runs on the isolated network.
3. It needs no account or key.

ZAP meets all three.

## Keeping it healthy

| How often | What |
|---|---|
| Every failure | A nightly FAIL is triaged the same day. If an outside change caused it (a new image, a feed format), the fix is a normal pull request. A **flaky** check is a bug: it is fixed, never skipped or retried silently. |
| Weekly | Merge Dependabot updates once CI is green. Check the CodeQL, Dependabot and secret-scanning alerts. Images pinned by digest in `ci/` (red team, browser, ZAP, Floci) are bumped by hand each release. |
| Each release | `docs/audits/X.Y.Z.md` reviews every change; the release gate needs "Open confirmed findings: 0" ([releasing](RELEASING.md)). The red-team totals in the README and REDTEAM.md are updated from the release's report. |
| Quarterly | Review the GAPs: close one, or say why it stays. Re-read the ATT&CK techniques used by attacks on small Linux servers and add a check for a new one. Rerun the fuzzers once with `FUZZ_N=100000`. |

**Reproducing a run locally.** Use Docker, Python 3 and the built wheel
(`python3 ci/build_dist.py`):

```bash
bash ci/redteam/run.sh                 # results in redteam-out/ (REPORT.md, results.jsonl, mails)
ZAP=1 bash ci/redteam/run.sh           # with the nightly ZAP scan
KEEP=1 bash ci/redteam/run.sh          # leave the containers up to look around
FUZZ_N=20000 FUZZ_SEED=42 python3 -m pytest -q guard/tests/test_fuzz.py
```

A fuzz failure prints its seed. `FUZZ_SEED` with that number repeats it exactly.
