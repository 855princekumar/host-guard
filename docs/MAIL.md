# Mail that sorts itself

Every mail host-guard sends has the same three-part subject, so an inbox can sort by
severity, then by kind, then by server, and a filter can route each kind:

```
[P1 Critical]  Intrusion    | web-01 | Intrusion signs on the server
[P1 Critical]  Advisory     | web-01 | 2 security warning(s) for this server
[P2 Attention] Attack       | web-01 | Blocked 3 address(es)
[P2 Attention] Host change  | web-01 | New login account: support; SSH key added
[P2 Attention] Backup       | web-01 | Restore test FAILED
[P2 Attention] Health       | web-01 | Disk 91% full
[P3 Info]      Advisory     | web-01 | 4 new security notice(s)
[P3 Info]      Backup       | web-01 | Restore test passed
[Resolved]     Health       | web-01 | Disk back under the limit
[Daily]        Daily report | web-01 | Daily report: all good
```

## Severity

| Severity | Meaning | Examples |
|---|---|---|
| **P1 Critical** | act now; always sent at once, marked high importance | a second root account, a miner, a library preloaded into every program, root logging in from the internet, an actively exploited vulnerability in software on this server |
| **P2 Attention** | look today | addresses banned (brute force, probes, floods), a changed security file or new SSH key, a failed backup or restore test, a full disk, an expiring certificate |
| **P3 Info** | for the record | security notices for installed packages, a passed restore test, the weekly scan |
| **Resolved** | an open problem is gone | |
| **Daily** | the daily report | |

## Categories

`Intrusion`, `Attack`, `Host change`, `Advisory`, `Backup`, `Health`, `Updates`,
`Scan`, `Daily report`, `Test`.

## Headers for filters

| Header | Example |
|---|---|
| `List-Id` | `host-guard Intrusion <intrusion.web-01.host-guard>` |
| `X-Host-Guard-Severity` | `P1`, `P2`, `P3`, `Resolved`, `Daily` |
| `X-Host-Guard-Category` | `Intrusion` |
| `X-Priority`, `Importance` | `1`, `high` (P1 only) |

Gmail filters (Settings, Filters, Create a new filter):

| Search | Action |
|---|---|
| `subject:"[P1 Critical]"` | star, mark important, never send to spam, label `host-guard/critical` |
| `list:attack.web-01.host-guard` | label `host-guard/attacks` |
| `subject:"[Daily]" from:(your sender)` | label `host-guard/daily`, skip the inbox if you like |

Outlook and other clients can filter on the subject prefix the same way.

## No flood of similar mails

* The same open problem mails once, then again only after `COOLDOWN_H` hours (6), and
  once more when it is resolved.
* P2 and P3 mails of one category are limited to `MAIL_MAX_PER_HOUR` an hour (4). More
  are held: the next mail of that category lists them under "Held back in the last hour
  (flood protection)", and the daily report counts them. An attack that trips a ban every
  few minutes gives a handful of mails an hour, not hundreds.
* Never held: P1 mails, resolved mails, the daily report, and every `Intrusion` and
  `Host change` mail. Those are signs of someone on the server; holding them would let an
  intruder bury the alert that matters under a few noisy ones (the red team tried: HOST-9).
  Flood protection applies to what outsiders can trigger at volume (bans, health, backups,
  notices).

## Every mail has a plain-text and an HTML part

The HTML part shows a coloured banner for the severity, an at-a-glance table and
sections; the plain text is the same content. Everything taken from logs is escaped,
since a log line can carry an attacker's text.
