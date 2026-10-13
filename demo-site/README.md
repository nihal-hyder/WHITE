# VELOUR — WHITE demo storefront

A complete, good-looking **clothing & footwear** store that you run on your own computer, so you
can test WHITE without owning a public website and without breaking any hosting provider's rules.

It is a real, working front end: browse the shop, open a product, pick a size, add to the bag,
change quantities, go through a checkout, and sign in as a customer or as staff (the admin console
shows an orders dashboard). The cart lives in your browser (localStorage); nothing is sent anywhere,
no payment is taken and **no card details are ever requested**.

It ships in two configurations:

| Configuration | What the server does |
| --- | --- |
| **weak** (default) | No security headers, an insecure session cookie, an `Apache/PHP` version banner, directory listings enabled, well-known sensitive files exposed (`/.env`, `/.git/HEAD`, `/.DS_Store`, `/server-status`, `/phpinfo.php`), a debug error page, an insecure newsletter form, and revealing `robots.txt` / `sitemap.xml` |
| **hardened** | A strong Content-Security-Policy, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, a `Secure`/`HttpOnly`/`SameSite` cookie, no version banner, directory listings off, sensitive files not served, a clean 404, and tidy `robots.txt` / `sitemap.xml` |

These are **real server misconfigurations**, not fake data and not exploitable code. WHITE finds them
by actually scanning the running site.

## Run it

Open two terminals in the WHITE folder (activate the virtual environment in each).

**Terminal 1 — start the store**
```powershell
python demo-site\serve.py
```
It serves at `http://127.0.0.1:8443/` and listens only on your computer. Open it in a browser to
shop around.

**Terminal 2 — scan it with the CLI**
```powershell
white scan http://127.0.0.1:8443/ --authorized --allow-private-network
```

**Or scan it with the GUI**
```powershell
$env:SUPABASE_URL=""; $env:SUPABASE_PUBLISHABLE_KEY=""; $env:WHITE_ALLOW_PRIVATE_TARGETS="true"
white serve
```
Open <http://127.0.0.1:8000>, choose **New scan**, enter `http://127.0.0.1:8443/`, tick the
authorization box and start. The report, charts and PDF all work.

## Show both at once (vulnerable vs fixed, side by side)

To present "this one has vulnerabilities, this one doesn't" live, run **both** configurations at the
same time on two ports, in two separate terminals:

**Terminal 1 — the vulnerable store**
```powershell
python demo-site\serve.py weak 8443
```

**Terminal 2 — the fixed store**
```powershell
python demo-site\serve.py hardened 8444
```

Now open both in your browser — `http://127.0.0.1:8443/` (vulnerable) and
`http://127.0.0.1:8444/` (fixed) — they look identical. Then scan each (in a third terminal, or
two tabs of the GUI):

```powershell
white scan http://127.0.0.1:8443/ --authorized --allow-private-network   # ~20 findings
white scan http://127.0.0.1:8444/ --authorized --allow-private-network   # 2 findings
```

The vulnerable one reports around 20 findings (including a Critical `.env` exposure); the fixed one
reports 2 (both only because localhost has no HTTPS — see below). Put the two reports next to each
other and the difference is obvious.

> `--allow-private-network` is what lets WHITE scan your own machine; it also lets you use a second
> local port like 8444. Never use it against websites that are not yours.

## See the difference (one site, switch back and forth)

1. With the store on its default **weak** configuration, scan it. WHITE reports around **20**
   findings, including a **Critical** exposed `.env`, two **High** issues, and a spread of
   Medium/Low/Informational ones.
2. Stop the store (Ctrl+C), run `python demo-site\switch.py hardened`, start it again
   (`python demo-site\serve.py`) and scan once more.
3. WHITE now reports just **2** findings, and the dashboard's **Progress over time** chart (or the
   report's comparison) shows **18 issues no longer detected**.

Run `python demo-site\switch.py weak` to go back.

### The two findings that remain in hardened mode

Both are because the demo runs on plain `http://` on your computer, where there is no HTTPS:

- **Website is not available over HTTPS**
- **Form sends information over an unencrypted connection** (any form on an HTTP page is, by
  definition, submitted without encryption)

On a real site served over HTTPS, both of these clear as well. They are left visible on purpose, as
an honest reminder that you cannot fully secure a site without HTTPS.

## What's inside

```
demo-site/
  serve.py              local web server that applies the active configuration
  switch.py             swap between weak and hardened
  active-config.json    the configuration currently in use (written by switch.py)
  public/               the storefront (shared pages, CSS, JS, product images)
    index.html          home (swapped per configuration)
    shop, product, cart, checkout, login, account pages
    admin/              staff login + orders dashboard
  configs/              the weak and hardened variants of index / config / robots / sitemap
  weak-extras/          the sensitive files served only in weak mode (safe, clearly-labelled demos)
```

Everything served is static and harmless. The admin and customer logins are demonstration gates
only (any details proceed); there is no real authentication, database or payment, and nothing is
stored on a server. This keeps the project safe to run locally while still giving WHITE a realistic,
full storefront to scan.
