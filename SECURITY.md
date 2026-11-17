# Security policy

host-guard runs as root on production servers, so security reports matter most.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private reporting
([Security > Report a vulnerability](https://github.com/855princekumar/host-guard/security/advisories/new))
or write to the maintainer through the contact on
[github.com/855princekumar](https://github.com/855princekumar).

Include what an attacker needs (local user, network position, a crafted log line,
...), the impact, and steps to reproduce. You will get an answer within 7 days,
and credit in the advisory if you want it.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | yes |
| 0.1.x | no, update |

## What is in scope

- Anything that lets a non-root user, a network attacker or text in a log, feed or
  advisory run commands, read a secret, change what host-guard does, or hide from it.
- The panel: authentication, sessions, CSRF, the root and unprivileged split.
- Secrets showing up anywhere but `/etc/host-guard/.env`.
- Mail: header injection, HTML injection.

## Design rules the code keeps

- One root-only file holds every secret; nothing prints, logs or mails one.
- Every value that reaches a shell is validated or quoted (`shlex.quote`); recipients
  must be plain addresses.
- Everything the server reports is HTML-escaped in mail and in the panel; a
  subject cannot add a header.
- The panel runs unprivileged and reads only a status file root writes for it.
- CI: Bandit, gitleaks over the whole history, ShellCheck, `systemd-analyze`, and
  tests for each of the rules above.
