# Login fix: "Forbidden (cross-origin form post)"

Root cause: the app sent `Referrer-Policy: no-referrer`; browsers then send `Origin: null` on form POSTs, and the login guard refused every `Origin: null`.

Changes (app.py only, plus tests/test_login_origin.py):
- Referrer-Policy is now `same-origin`.
- New `_origin_ok()`: exact scheme + hostname + port comparison; `Sec-Fetch-Site` cross-site/same-site refused; `Origin: null` accepted only with `Sec-Fetch-Site: same-origin`; missing Origin allowed only for non-browser clients or same-origin/none.
- CSRF, session cookie, MFA, rate limits, RBAC and trusted-proxy handling are unchanged. `--set-login` was not changed (its 12-character and username rules are correct).

Recover admin access (never use --reset): `python app.py --set-login` then `python app.py`, and open http://127.0.0.1:5000 (not localhost).
Tests: python tests/test_login_origin.py
