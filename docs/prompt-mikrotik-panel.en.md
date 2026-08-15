# The prompt behind a MikroTik fleet management panel

Written after building Tikpilot. The first section can be copied as is and
handed to a model. The rest are appendices, meant to be given out as the
work goes: all at once they fit neither in the model's head nor in yours.

The valuable part here is not the feature list. Anyone can invent a feature
list. Section 3, the RouterOS gotchas, took months of running a live fleet
to collect.

Русская версия: [prompt-mikrotik-panel.md](prompt-mikrotik-panel.md)

---

## 1. The main prompt

> You are writing Tikpilot: a self-hosted web panel for managing a fleet of
> MikroTik routers. I am a network administrator with 49 sites: shops,
> canteens and oilfield locations. Some sites are deep in the taiga, where
> the internet is bad and expensive. All of them are joined to a central
> WireGuard hub. I work alone, with no help, and a trip to a far site costs
> a day and real money.
>
> The panel has to answer four questions and do four things:
>
> 1. What is down right now, and for how long.
> 2. Which RouterOS version sits where, and what can be upgraded.
> 3. What is connected at each site.
> 4. Whether there is a recent configuration backup.
>
> And it has to: run actions across selected sites at once, take backups on
> a schedule, upgrade RouterOS and wait for the device to come back, and set
> up WireGuard spokes.
>
> **Stack:** Python 3.10+, FastAPI, Jinja2, SQLite, librouteros. A single
> process running on a VM with one gigabyte of memory. No Redis, no Celery,
> no Node.js, no ORM, no frontend build. JavaScript stays plain, with no
> framework. Not a single request to an external CDN: the panel must work in
> a network with no internet, and that is a hard requirement. Charts are
> rendered as SVG on the server.
>
> **Interface:** server-side rendering, pages in Jinja2. Two languages,
> Russian and English, switchable from the header. Dark and light themes.
>
> **How to work:** first ask me about anything ambiguous, then propose a plan
> in stages, then do one stage at a time and show the result. Run the tests
> after every stage. Do not show me the whole code, show me what was done and
> what was verified.
>
> Before you start, read the appendices: operating conditions, RouterOS
> gotchas, security rules, and the requirements for tests and style.

---

## 2. Appendix A. Operating conditions

This is not background. It is where almost every decision comes from. Hand
it over together with the main prompt.

- **Links are bad and expensive.** Satellite, LTE with losses, radio bridges
  between buildings. Every extra byte costs money. Hence: do not poll more
  often than needed, do not pull more than needed from a site, and keep the
  connection open instead of reconnecting.
- **There is one administrator.** The panel must not require anyone on duty.
  Everything that can be computed and shown in advance should be.
- **Site visits are expensive.** Any action that can leave a site
  unreachable must be either reversible or guarded. A firewall mistake on a
  distant site is a business trip.
- **No messenger notifications.** On bad links sites flap, and a stream of
  notifications makes the panel useless. History is read with your eyes,
  when there is a reason.
- **Some sites are shown to contractors.** A public link is needed with
  names and state only, without addresses, versions or error texts.

---

## 3. Appendix B. RouterOS gotchas

The most valuable part. Every line here cost a separate failure.

### Protocol and library

- **librouteros turns `true` and `false` into real Python booleans while
  parsing the reply.** A comparison against the string `"true"` will never
  match, and will fail silently. Write one helper and use only that.
- **Set the connection encoding explicitly: `encoding="utf-8"`.** Otherwise
  non-Latin text in comments and names arrives as garbage.
- **Usernames and passwords must be ASCII.** RouterOS refuses non-ASCII
  credentials and the error is unhelpful. Check before connecting and say so
  in plain language.
- **A stream of short TCP connections to port 8728 makes weak devices log
  `possible SYN flooding`.** Keep persistent sessions: one login per device,
  then commands over the open connection. As a bonus, the router log is not
  buried under authentication records.

### Versions and upgrades

- **Versions compare as numbers, not as strings.** 7.9 is lower than 7.21.
  String comparison says the opposite, and the panel will offer an "upgrade"
  backwards.
- **A downgrade cannot be done by a normal install.** RouterOS only installs
  something newer. Downgrading is a separate `/system package downgrade` and
  only from files already uploaded to the router.
- **Check free space before an upgrade.** The package will not fit, the
  device will stay on the old version, and the message about it will be
  useless.
- **Downloading and installing must be separate steps.** On a thin link the
  download takes hours while the device keeps working. Rebooting it is a
  separate step, done at a convenient time.
- **RouterOS may defer the reboot command itself.** First wait until the
  device has actually disappeared, and only then wait for it to come back.
  Otherwise the panel cheerfully reports success without rebooting anything.
- **Always verify the version after it returns.** A device being reachable
  does not mean the upgrade went in.

### WireGuard

- **A peer's `allowed-address` decides which spoke a packet is encrypted
  for, but writes nothing into the routing table.** Networks behind the
  tunnel need ordinary routes.
- **Use the peer tunnel address as the gateway in a route, not the interface
  name.** With several peers on one interface, a route through the interface
  does not tell the router which one to hand the packet to, and it works
  incorrectly.
- **`allowed-address` arrives as one comma-separated string.** When looking
  for a free tunnel address, parse every entry, or the panel will offer an
  address that is already taken fifty times over.
- **The spoke private key is shown once and stored nowhere.** There is no
  reason to keep it in the panel, and the temptation is strong.

### Clients behind a site

- **One source is never enough.** Names and addresses come from DHCP leases,
  statically configured devices show up in ARP, the physical port is known
  only to the bridge host table, and wireless clients with all their signal
  data come from the registration table. Merge it all by MAC: names and
  addresses change, the MAC does not.
- **In RouterOS 7 the port field in the bridge host table is
  `on-interface`; in version 6 it was `interface`.** Read both.
- **The router lists its own interfaces in the host table too**, flagged as
  local. Drop them, or the router ends up among its own clients.
- **The ISP equipment is identified by the default route.** An ARP entry for
  the gateway is not a client.
- **`bridge` in a "port" column does not answer the question "where is the
  cable plugged in".** Show a real port, a wireless interface, or nothing.
- **A comment written by a human on the router beats the name a device
  reports about itself.** If somebody already labelled the box in the DHCP
  lease, show that.

### Monitoring

- **Damping belongs on the way down only.** A couple of missed probes before
  painting a site red is right. The same damping on recovery is fatal: on a
  lossy link one miss resets the counter of good checks, and a site that is
  reachable nine minutes out of ten stays "offline" forever. Going back
  online happens on the first successful reply.
- **Absorb flapping in the history, not in the status.** Mark an outage
  shorter than a threshold as a flap: it stays out of the downtime total and
  out of the event feed, but shows up in a separate list of flapping sites.
  A panel that lies about availability is worse than a noisy one.
- **Targets that do not answer ICMP must be told apart from packet loss.**
  ISP gateways often stay silent entirely, and a solid 100% loss hides the
  real problems. Suspend a silent target and re-check it once an hour.
- **Spread the checks out in time.** Fifty simultaneous connections through
  one tunnel is a spike that makes the checks themselves start missing.
- **Do not check devices that are busy with a bulk job.** A miss during a
  reboot is expected and only spoils the status.
- **Public DNS is a poor availability target.** It answers out of courtesy,
  rate-limits ICMP per source, and can stop at any moment. The meaningful
  targets are the ISP gateway and the hub: the first tells you about your
  own link, the second about the path to the centre, and the difference
  between them is the diagnosis.

---

## 4. Appendix C. Security rules

- **Device passwords are encrypted in the database** (Fernet), the key lives
  in a separate file with mode 600 and never reaches the repository.
- **Dangerous actions are marked as such** and require confirmation with the
  list of devices. Rebooting forty sites must not be one click away from
  rebooting one.
- **Batches instead of "all at once".** Upgrades go in groups with a pause,
  so a human has time to stop them when something goes wrong.
- **Deferred start.** Anything that reboots a site must be able to wait for
  a maintenance window.
- **Rights by capability and by scope.** A contractor sees their own group
  and never sees passwords.
- **The panel is restricted by network** with a list of trusted subnets,
  while the public status pages stay reachable from outside.
- **Passwords and keys are stripped from logs** before the line reaches a
  buffer or a file.
- **Login attempts are limited** with a growing delay, counted per address,
  and checked before the password is verified.
- **The default account is created only on an empty database**, so a deleted
  administrator does not rise again on restart.

---

## 5. Appendix D. Tests

- **No mocking of the library.** Write a stub that speaks the real RouterOS
  API protocol. A mock accepts any mistake in a command; a stub catches it.
- **Tests that really wait** (reboot, slow download, deferred start) go
  behind a separate mark. The quick run skips them, the full run before a
  release does not.
- **One command to verify a change:** tests, translation completeness and
  module imports. A forgotten translation string is the most common small
  breakage, and you want to hear about it immediately.
- **Tests use the panel's real error texts**, not invented ones. An invented
  string will end up on a page and fail the translation check, and it will
  be right to.
- **A second test client must not be opened with `with`:** its exit stops
  the background worker for the whole process, and jobs in later tests hang
  until they time out.
- **The background monitor is switched off in tests** by an environment
  variable, otherwise failures become mysterious.
- **The translation completeness check must not depend on test order.**
  Otherwise it fails intermittently, and people stop reading it.

---

## 6. Appendix E. Two languages

- Strings are written in templates in the source language as usual, and the
  markup is added automatically: a Jinja extension wraps the text during
  template preprocessing. Nobody writes `_("...")` by hand.
- The source text itself is the message id. The English catalogue is a
  dictionary in a single file.
- Strings assembled from pieces at runtime are described by pattern rules.
- Plural forms are stored as one string with a separator, so a translator
  does not need to know the internal conventions.
- The test fails on any untranslated string. That matters more than it
  sounds: without it the second language rots within a week.

---

## 7. Appendix F. Style

- **Comments explain why, not what.** `# increment the counter` is noise;
  `# RouterOS only reports this on the second poll` is worth writing.
- **No em dashes in anything a user sees.** A colon, a comma, a full stop or
  a rearranged sentence. The single exception is a lone dash standing in for
  a missing value in a table.
- **Interface texts are written in the administrator's language, not the
  developer's.** "The site is not answering" instead of "connection
  refused", "down for 4 minutes" instead of "downtime 240s".
- **Hints under form fields explain the consequences**, not the name of the
  field. "0 means all at once, batches are safer" beats "batch size".
- Python: the standard library, type hints where they help, lines up to 100
  characters.

---

## 8. Appendix G. Order of work

The breakdown that worked. Every stage ends with a working panel, not a
half-finished one.

1. Skeleton, database, password encryption, sign-in.
2. RouterOS client and the registry of bulk actions.
3. Background job worker with progress and history.
4. Pages: device list, device card, dashboard.
5. Availability monitoring over persistent sessions.
6. RouterOS upgrades with waiting for the device to return.
7. Backups, schedule, keeping the last N copies.
8. Metrics and charts.
9. Rights and scopes.
10. The second language.
11. WireGuard.
12. Clients behind the sites.
13. Documentation, licence, CI.

---

## 9. Definition of done

- The panel comes up with one command on a clean machine and works without
  internet.
- All tests are green and no string is left untranslated.
- Not a single external CDN request in the templates.
- No real addresses, passwords, keys or data files in the repository.
- Every action that can leave a site unreachable requires confirmation and
  goes into the audit log.
- Errors on a page say what to do, not only what happened.
