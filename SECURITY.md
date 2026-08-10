# Security Policy

> The code in this repository was written by an AI model and has not been
> reviewed line by line by a human. There is a test suite, and the panel runs a
> real 49-device fleet in production, but security reports are especially
> welcome here.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository.

Expect an acknowledgement within a few days. This is a spare-time project, so
please be patient with the fix timeline. Anything that exposes device
credentials will be treated as urgent.

## What matters most here

Tikpilot stores credentials for an entire router fleet. In rough order of
severity:

1. **Anything that leaks device passwords:** decryption without the key, or
   exposure through an API response, a template, an export or a log line.
2. **Authentication bypass:** reaching any page or API endpoint without a valid
   session.
3. **Remote command execution on the managed devices.** The app can run arbitrary
   RouterOS commands by design, so any path that reaches that without an
   authenticated admin is critical.
4. Session fixation, CSRF on state-changing endpoints, stored XSS in device names
   or job results.

## Known design limits

These are deliberate trade-offs, not bugs. Please do not report them as
vulnerabilities, but do argue with the reasoning if you think it is wrong.

* **Device passwords are reversibly encrypted (Fernet), not hashed.** They have to
  be, because the app logs into the devices with them. The key lives in
  `data/fernet.key`. Anyone who can read that file and the database has the
  passwords, so the `data` directory is the thing to protect. The systemd unit
  restricts access to it.
* **There is no HTTPS built in.** The app listens on plain HTTP and expects to sit
  behind nginx or another reverse proxy where TLS is needed. Set `COOKIE_SECURE=1`
  when you do that.
* **Permissions are enforced server-side, per account.** Each user has a set of
  capabilities and a scope of devices. If you find a way to act outside your
  scope or to run an action you were not granted, that **is** a security report
  and a welcome one.
* **The default credentials are `admin` / `admin`.** The installer generates a
  random password, the Docker path does not. The UI nags until it is changed.

## Deployment advice

* Do not expose the panel to the internet. It belongs on a management network or
  behind a VPN.
* Give the RouterOS API user the minimum policies (see the README) and restrict it
  with `address=` to the server's address.
* Back up `data/fernet.key` separately from the database. Losing it means
  re-entering every device password; leaking it together with the database means
  losing every device password.
