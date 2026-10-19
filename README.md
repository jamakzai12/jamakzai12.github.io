# Free tools by @itzSaasified

Small free tools for people running cold email. No login, no backend, nothing stored.

## Sending domain checker

https://jamakzai12.github.io/domain-checker/

Type a sending domain and see, in plain words:

- **MX**: does mail for the domain go anywhere, and to which provider
- **SPF**: exactly one record, a sensible ending (`~all` / `-all`), and how many of the 10 DNS lookups it uses ([RFC 7208 §4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4)), following every include
- **DKIM**: a key under your selector, or under common selectors if you leave it empty
- **DMARC**: one record with a valid policy; `p=none` is the minimum Gmail, Yahoo and Outlook ask bulk senders for
- **Website**: whether the domain points anywhere

Lookups run in your browser against Cloudflare's public DNS-over-HTTPS (Google's as a backup). Share results with `?d=yourdomain.com`.

### Checked on 19 Oct 2026 against public domains

| Domain | MX | SPF | DKIM | DMARC | Website |
|---|---|---|---|---|---|
| google.com | Pass (Google Workspace) | Pass, 1/10 lookups | Check (selector not common) | Pass, p=reject | Pass |
| microsoft.com | Pass (Microsoft 365) | Pass, 7/10 | Pass (selector2) | Pass, p=reject | Pass |
| github.com | Pass (Microsoft 365) | Check, 10/10 (hand-counted with dig: 8 + 1 + 1) | Pass | Pass, p=quarantine | Pass |
| stripe.com | Pass (Google Workspace) | Pass, 7/10 | Pass | Pass, p=reject | Pass |
| example.com | Fix (null MX) | Pass, 0/10 | Fix (empty key) | Pass, p=reject | Pass |
| a domain that does not exist | Fix | Fix | Check | Fix | Check |

Fonts: Source Serif 4 and Geist Mono, SIL Open Font License.
