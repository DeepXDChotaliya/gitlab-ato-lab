# gitlab-ato-lab
# Password Reset Type-Confusion Lab (VulnBank)

A local, self-contained lab recreating the vulnerability class behind a
real $35,000 GitLab account takeover a password-reset endpoint that
expects `email` to be a string but silently accepts an array, mailing the
reset token to every address in that array while resolving the account
from just the first one (CWE-843, Access of Resource Using Incompatible
Type).

Everything here is self-contained. No real network calls, no third-party
target. Only test this locally.

## Original research

This lab is a re-creation for educational purposes, based on the publicly
disclosed report:

**Account Takeover via Password Reset without user interaction**
Reported by [asterion04](https://hackerone.com/asterion04) to GitLab via HackerOne
Bounty: $35,000 · Severity: Critical (10.0) · CWE-843
Report: https://hackerone.com/reports/2293343

All credit for the original discovery goes to the reporter. This repo
exists to teach the underlying vulnerability class, not to claim the
original finding.

## Setup

```bash
pip install flask
python3 app.py
```

Open http://127.0.0.1:5000

There's no real SMTP in this environment, so instead of actually emailing
anyone, every "sent" email lands in an in-app mailbox viewable at
`/mailbox/<address>`. If you want to demo real email delivery later, swap
`send_mail()` in `app.py` for an SMTP call (e.g. `smtplib` with Mailtrap or
your own domain) — the vulnerable/patched logic doesn't change at all.

## Attack walkthrough (matches the original report's steps)

1. Register two accounts: `victim@example.com` and `attacker@example.com`.
2. Log out. Go to **Forgot password**, and submit `victim@example.com`
   normally first — this is what a legitimate request looks like on the wire:
   ```json
   {"email": "victim@example.com"}
   ```
3. Intercept that same POST to `/forgot-password` in Burp Suite.
4. Change the JSON body to an array with your own address appended —
   this is the "Content-Type Converter -> array" trick from the GitLab
   report, done natively here since the endpoint already speaks JSON:
   ```json
   {"email": ["victim@example.com", "attacker@example.com"]}
   ```
5. Forward it. Open `/mailbox/attacker@example.com` — you'll find the
   *same* reset token that went to the victim's mailbox.
6. Click the reset link, set a new password. You're now logged in as
   `victim@example.com`.
7. On the dashboard, hit **Switch to patched mode** and repeat step 4 —
   you'll get `400 {"error": "email must be a string"}` instead.

## What's actually happening in the code (`app.py`)

- **Vulnerable branch**: no type check on `email`. If it's a list, every
  element becomes a delivery address, but the account is looked up using
  only `recipients[0]`. Token is scoped correctly to one user — the bug is
  entirely in who gets *told* that token.
- **Patched branch**: `isinstance(email_field, str)` guard rejects
  anything that isn't a plain string before any DB lookup or mail
  dispatch happens.
- Password reset itself always operates on `user_id` bound to the token,
  never on an email string re-entered later — so the fix is narrow and
  cheap, which is a good talking point: this is a one-line validation
  miss, not an architectural flaw, and that's exactly why it slipped
  through review and paid out $35k.

## Suggested video structure

1. **Hook** — show the HackerOne report, the $35k payout, "no user
   interaction."
2. **Explain the concept** — type confusion / loose parsing (CWE-843):
   backend expected a string, got a list, didn't check.
3. **Live demo on your own lab** — the walkthrough above, screen-recorded,
   Burp Suite visible.
4. **Show the fix** — flip the toggle, replay the same request, get 400.
5. **Takeaway for viewers** — why "expected type" validation matters on
   every field that ends up in a security-sensitive lookup, not just
   auth headers.

Standard disclosure note worth saying out loud on camera: everything here
runs on `127.0.0.1`, nothing was tested against a live target without
authorization, and viewers should only try this against the app in this
repo or something they have explicit written permission to test.
