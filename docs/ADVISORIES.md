# Advisories (shield)

Every 6 hours host-guard lists what runs on the server and checks it against official,
machine-readable vulnerability sources. It mails what matters by tier, and it can fix Critical
findings by itself after a hold the admins can stop. It runs plain rules over published data:
no AI model or agent decides anything.

```bash
sudo hostguard shield                 # a run now (the timer runs it every 6 hours)
sudo hostguard inventory              # what runs here, and what is not covered
sudo hostguard findings               # open findings with their IDs
sudo hostguard hold ID                # stop the automatic fix of one finding
sudo hostguard fix ID                 # fix it now (restore point first)
sudo hostguard ignore ID "reason"     # does not apply here
sudo hostguard undo RESTORE_POINT     # put a fix back
sudo hostguard sources                # the sources, when each was last read
sudo hostguard sources add NAME https://URL [feed|page]
sudo hostguard sources remove ID
```

## What is checked

| Part | Where from |
|---|---|
| OS packages, and which ones running programs load | dpkg, apk or rpm, plus `/proc/*/maps` |
| Containers and their packages | every running container, read inside it |
| Upstream server programs (nginx, PHP, Java, Node.js, OpenSSL, OpenSSH, Redis, PostgreSQL, MariaDB, Python, sudo, runc, Docker) | their own version output, on the host and in containers |
| Python packages and Java archives on disk | the files themselves |

`hostguard inventory` lists what is **not covered** as well, so nothing is skipped without
anyone knowing.

## Sources

**Official sources decide:**
- CISA Known Exploited Vulnerabilities;
- OSV (distributions, PyPI, npm, Maven, GitHub advisories);
- NIST NVD;
- FIRST EPSS;
- endoflife.date;
- vendor advisory pages such as nginx.org.

**Context sources never start anything.** Research labs, the oss-security list, security
news, and any source the admins add are read for what they say about software on this server.
The mails show it next to the findings.

### Adding a source

Admins can add the sources they trust from the dashboard (**Advisory sources**) or with
`hostguard sources add`. An added source:

- must be an `https` address on a public host. It is checked when added, again before each
  read, and on the connection actually made, through every redirect. This keeps it away from
  the server itself, its network and the cloud metadata service;
- is always context, never official;
- is mailed to every admin when added or removed;
- counts toward the limit of `SOURCES_MAX` (20). From the dashboard, at most 10 changes an
  hour, each confirmed with a fresh code mailed to the admin.

### Reading web pages through a reader

A **web page** source (`page`) is read as text. With `READER` set, for example to the Jina
Reader at `https://r.jina.ai/`, pages come back as clean Markdown. The reader's own key, if
it has one, goes in `.env` as `READER_KEY`. Without a reader, the page is read directly and its
tags are stripped. Official sources never go through the reader.

## Tiers

| Tier | When | Mail |
|---|---|---|
| Critical | exploited (CISA KEV); or CVSS 9+ (or 7+ with EPSS 0.5+) in something running | at once (P1), with Fix and Hold reply lines when replies are on |
| Moderate | CVSS 7+ or EPSS 0.1+; a Critical one that is installed but not running, or a library inside an image | one mail per run, and the daily report |
| Low | everything else, and any finding with no fix released yet that is not exploited | the daily report counts them |

A finding with no fix released yet is Low unless it is exploited: there is nothing to install
yet. It moves up when the fix arrives.

## Automatic fixes

Automatic fixes apply to Critical findings only, and only with `AUTO_FIX=critical`:

1. **The hold.** The finding's first mail says when the fix will run, `AUTO_FIX_HOLD_H` (24)
   hours later. Any admin can hold it, or fix it at once, in three ways:
   - by reply ([approvals](APPROVALS.md));
   - on the dashboard;
   - on the server.
2. **The window.** The fix runs inside `FIX_WINDOW` (for example `Sun 03:30-05:00`), or at any
   time when that is empty.
3. **A restore point first:** the old package versions or the old image, `/etc`, and a fresh
   backup.
4. **The fix:**
   - an OS package: `apt-get install --only-upgrade` of exactly the affected packages;
   - a container on a floating tag: `docker compose pull` and `up` of that one service.

   Anything else is listed with the manual step: a pinned image, an application dependency
   (shipped through the app's own CI), or a program installed by hand.
5. **A health check after.** If the server is not as healthy as before, the fix is rolled back
   by itself.
6. **A mail with the result,** the restore point, and the command to undo it.

## Settings

See [configuration](CONFIGURATION.md#advisories) for `AUTO_FIX`, `AUTO_FIX_HOLD_H`, `FIX_WINDOW`,
`READER`, `SOURCES_MAX` and the source URLs. `NVD_API_KEY` in `.env` raises NVD's rate limit
(optional).
