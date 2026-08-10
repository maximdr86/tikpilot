# Contributing to Tikpilot

Thanks for taking a look. A few honest expectations up front.

The code here was written by Claude, an AI model, working with
[maximdr86](https://github.com/maximdr86), who set the requirements and tests
every version on a live fleet of 49 devices. See
[How this project came about](README.md#how-this-project-came-about). It is a
spare-time project, so:

* Bug reports about **real fleets** are the most valuable thing you can send.
  Almost every fix in the changelog came from something breaking on live hardware.
* Pull requests are welcome, but please open an issue first for anything larger
  than a fix. It saves you writing code that does not fit the design.
* Response time is "when there is an evening free", not "within 24 hours".
* Human-written pull requests are welcome and reviewed the same way as anything
  else. The origin of the existing code does not set a precedent for yours.

Issues and pull requests in **Russian or English** are both fine.

---

## Setting up

```bash
git clone https://github.com/maximdr86/tikpilot.git && cd tikpilot
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env
```

You do **not** need a MikroTik device to develop or run the tests.
`tests/fake_router.py` is a stub that speaks the real RouterOS API binary protocol
and can serve files over FTP.

Run the app:

```bash
uvicorn app.main:app --reload --port 8080
```

Check your change with one command:

```bash
./check.sh          # fast: tests without waits, translations, module import
./check.sh --all    # everything, including tests that wait for real time
```

The fast run skips tests marked `slow`. Those wait for real time: a device
coming back after a reboot, a slow package download, a deferred job. The waiting
there is the thing being tested, not overhead, so they live in their own group
and run before a release and in CI.

The plain pytest way still works:

```bash
DATA_DIR=/tmp/tikpilot-test MONITOR_ENABLED=0 pytest -q -m "not slow"
```

`MONITOR_ENABLED=0` matters: otherwise the background monitor thread runs during
the tests and makes failures confusing.

Two things worth knowing before you add a test:

* **Do not open a second `TestClient(app)` with `with`.** Its shutdown stops the
  background worker and the monitor for the whole process, and jobs in later
  tests then hang forever. Use the `_as(username)` helper, which logs a second
  user in without touching the lifespan.
* **Use the real error texts** the panel produces, not made-up ones. Invented
  strings land on the page and the translation completeness test flags them,
  rightly: there is nothing to translate them with.

---

## Before you open a pull request

1. **The tests pass.** All of them, not just the ones near your change.
2. **New behaviour has a test.** If it involves a device, extend the stub in
   `tests/fake_router.py` rather than mocking `librouteros`. The stub catches
   protocol-level mistakes that a mock would happily accept.
3. **New interface strings are translated.** Write labels in Russian in the
   templates as usual. `app/i18n.py` marks them automatically, so you do not add
   `_("...")` by hand. Then add the English value to `app/locales/en.json`.
   The test suite fails on any string that has no translation, so you will know.
4. **No external CDNs.** No `<script src="https://...">`, no web fonts, no chart
   libraries loaded from the network. The panel must work in an air-gapped
   network; that is a hard requirement, not a preference. Charts are rendered
   server-side as SVG in `app/charts.py`. The one browser library that is not
   written here, the terminal emulator, is vendored into `static/vendor/`
   with its licence and a note on how it was obtained. No bundler, no build
   step: a single file included with a `script` tag.
5. **No new heavyweight dependencies.** No Redis, no Celery, no Node.js, no ORM.
   The whole point is that this runs as one process on a 1 GB VM.
6. **Version bump and changelog.** Update `app/__init__.py` and add an entry to
   `CHANGELOG.md` describing what changed and *why* it mattered.

---

## Style

* Python: standard library conventions, type hints where they help, 4 spaces,
  lines under 100 characters.
* **Comments explain why, not what.** `# increment counter` is noise;
  `# RouterOS only reports this after the second poll` is worth writing.
  Existing comments are in Russian, keep the language of the file you are editing.
* **No em dashes in text the user sees.** Not in page copy, not in labels, not
  in error messages, in either language. Use a colon, a comma, a full stop, or
  split the sentence. The one exception is a lone `—` standing in for a missing
  value in a table cell, where it means "no data" rather than punctuation.
  `test_ui_texts_have_no_em_dash` enforces this; code comments are exempt.
* Templates: Jinja2, no logic beyond presentation.
* JS: plain, no framework, no build step. If it needs a bundler, it does not
  belong here.

---

## Adding a bulk action

This is the most common contribution and it is deliberately easy. Everything
happens in `app/actions.py`; the UI, the parameter form and the job execution are
picked up automatically. See the "Adding a new bulk action" section in
[README.md](README.md) for a worked example.

Things to get right:

* Set `dangerous=True` if the action changes configuration or interrupts service.
  The operator then gets a confirmation dialog.
* Set `disrupts_connection=True` if the device will reboot or the session will die.
  Otherwise the session pool keeps a dead connection and the next check is wrong.
* Raise `DeviceError("readable Russian text")` for expected failures. The text goes
  straight into the job result, where an operator reads it, so add an English
  entry for it in `app/locales/en.json` too. Messages assembled at runtime (with
  a timeout or a file name inside) go under `__patterns__` as a regex.
* Never assume a command succeeded because it did not raise. RouterOS is happy to
  accept commands and do nothing.

---

## Reporting a bug

Use the issue template. It asks for the RouterOS version and the device model,
and those two facts explain a surprising share of reports. Behaviour differs a lot
between 6.x and 7.x, and between a hAP ac lite with 16 MiB of flash and a CCR.

Please include:

* what you did, what you expected, what happened;
* the Tikpilot version (bottom of the sidebar, or **Settings → About**);
* the relevant part of the log (`journalctl -u tikpilot` or
  `docker compose logs tikpilot`).

**Redact before pasting.** Logs and screenshots contain site names, internal
addresses and API usernames.

---

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
