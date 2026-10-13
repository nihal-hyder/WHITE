# WHITE demo site

A small, fictional website ("Northwind Coffee Roasters") that you own and run **on your own
computer**, so you can test WHITE without owning a public website and without breaking any
hosting provider's rules.

It has two configurations:

| Configuration | What it contains |
| --- | --- |
| `weak` (default) | Missing security headers, an insecure cookie, a version banner, a password form that submits over HTTP using GET, mixed content, a credential-like HTML comment, revealing robots.txt and sitemap entries |
| `hardened` | Security headers, a protected cookie, no version banner, a safe form |

## Use it

Open two PowerShell windows in the WHITE folder.

**Window 1 - start the demo site**
```powershell
.\.venv\Scripts\Activate.ps1
python demo-site\serve.py
```
It runs at `http://127.0.0.1:8443/` and listens only on your computer.

**Window 2 - scan it with the CLI**
```powershell
.\.venv\Scripts\Activate.ps1
white scan http://127.0.0.1:8443/ --authorized --allow-private-network
```

**Or scan it with the GUI**
```powershell
$env:SUPABASE_URL=""; $env:SUPABASE_PUBLISHABLE_KEY=""; $env:WHITE_ALLOW_PRIVATE_TARGETS="true"
white serve
```
Open http://127.0.0.1:8000, choose **New scan**, enter `http://127.0.0.1:8443/`.

## See improvement over time

1. Scan the `weak` site (above).
2. Stop the demo site (Ctrl+C) and run `python demo-site\switch.py hardened`.
3. Start it again with `python demo-site\serve.py` and scan again.
4. The dashboard's **Progress over time** chart and the report comparison now show which issues are
   no longer detected. In testing, hardening resolved 10 of 15 findings. The remaining ones are real
   for a local site: no HTTPS on your own computer, Python's built-in folder listing, and the
   robots/sitemap notes.

Run `python demo-site\switch.py weak` to reset.

## Why not host it for free?

Free plans of common hosts do not allow security testing of the sites they host: Vercel Hobby does
not permit it, Netlify requires written permission, and Cloudflare restricts testing to domains you
register yourself. Running the demo locally avoids all of that.
