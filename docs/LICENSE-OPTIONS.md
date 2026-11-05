# Licence options (owner decision required; no LICENSE file has been added)
| Option | Effect | Consider when |
|---|---|---|
| Apache-2.0 | Permissive, explicit patent grant, requires notices | You want broad adoption and commercial use |
| MIT | Permissive, shortest text, no patent grant | Maximum simplicity |
| AGPL-3.0 | Network copyleft: hosted modifications must be shared | You want to stop closed hosted forks |
| GPL-3.0 | Copyleft for distributed copies only | Copyleft without the network clause |
| Source-available / proprietary | Not open source | You want to keep control |
Recommendation awaiting approval: Apache-2.0 for a security tool seeking adoption, or AGPL-3.0 if closed hosted forks are a concern. This is not legal advice. Check compatibility with bundled/vendored assets (Leaflet BSD-2, Chart.js MIT, Socket.IO client MIT: verify at vendoring time) and Python dependencies before choosing. Add `THIRD-PARTY-NOTICES` with verified licence texts at that time.
