# Contributing

Thanks for helping. host-guard guards production servers, so changes are small,
tested and easy to review.

## Ground rules

- **Python standard library only** in `guard/` and `panel/`. A new dependency is a
  new thing to patch on every server.
- **Every secret stays in `/etc/host-guard/.env`.** Never print, log or mail one.
- **Anything that reaches a shell is validated or `shlex.quote`d.** Anything that
  reaches HTML is escaped.
- **App-specific values are settings** with a neutral default (off when empty), and
  a profile in `examples/profiles/` when it helps others.
- **Plain words** in docs, mails and messages. No em dash character (CI checks):
  use a colon, comma or parentheses.

## Run the checks

```bash
python -m pytest -q guard/tests panel/tests
docker run --rm -v "$PWD:/src:ro" ubuntu:26.04 bash /src/ci/fresh_install.sh
bash ci/db_restore.sh            # needs Docker: real MariaDB and PostgreSQL backups
```

## Pull requests

1. Branch from `main`, one topic per pull request.
2. Add or change a test for what you changed; a bug fix starts with a test that fails.
3. Update the docs and `CHANGELOG.md` (under "Unreleased").
4. CI must pass: tests, fresh installs, database restores, Bandit, gitleaks,
   ShellCheck, systemd units, docs links, no em dash.

## Good first contributions

- A profile for your stack (`examples/profiles/`), tested on a real server.
- More signs for the intrusion watch, with a test.
- Support for another distribution's package manager in `guard/install.sh`.
