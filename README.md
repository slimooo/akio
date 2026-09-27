# Audit de sécurité navigateur — guide ANSSI

`anssi_web_audit.py` teste une application web au regard du guide ANSSI-PA-009 v2.0
[« Recommandations pour la mise en œuvre d'un site web : maîtriser les standards de sécurité côté navigateur »](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-recommandations_mise_en_oeuvre_site_web_maitriser_standards_securite_cote_navigateur-v2.0.pdf).

Chaque constat est rattaché à une recommandation `R1` à `R63` du guide.

> N'utilisez ce script que sur des applications que vous êtes autorisé à tester.
> Les contrôles sont non intrusifs (requêtes GET classiques, poignées de main TLS,
> une requête avec un en-tête `Origin` arbitraire, analyse statique du HTML/JS).

## Prérequis

Python 3.8+ — aucune dépendance externe.

## Utilisation

```bash
python3 anssi_web_audit.py https://exemple.fr

# Page authentifiée, points d'API supplémentaires, rapports JSON et HTML
python3 anssi_web_audit.py https://exemple.fr/compte \
    --cookie "session=…" \
    --extra-url https://api.exemple.fr/v1/me \
    --json rapport.json --html rapport.html -v
```

| Option | Rôle |
|---|---|
| `--cookie`, `-H "Nom: valeur"` | Auditer une page authentifiée |
| `--extra-url URL` | Contrôler aussi un point d'API (CORS, Content-Type) — répétable |
| `--scan-third-party` | Analyser aussi le JavaScript des domaines tiers |
| `--json`, `--html` | Générer un rapport |
| `--fail-on fail\|warn\|never` | Code retour pour l'intégration continue (défaut : `2` si au moins un ÉCHEC) |
| `-k` | Ne pas vérifier le certificat (environnements de recette) |
| `-v` | Afficher aussi les points MANUEL et N/A |

## Couverture

| Contrôle automatique | Recommandations |
|---|---|
| HTTPS, redirection HTTP→HTTPS, certificat, versions TLS 1.0–1.3, contenu mixte | R1 |
| HSTS (`max-age` ≥ 1 an, `includeSubDomains`) | R2 |
| `Content-Type`, `X-Content-Type-Options: nosniff` | R6, R34 |
| CSP : en-tête vs `<meta>`, `unsafe-inline`/`unsafe-eval`/`data:`, `default-src`, `frame-ancestors`, `connect-src`, report-uri, sources génériques | R13–R17, R19, R20, R37, R52 |
| `X-Frame-Options` | R18 |
| `Referrer-Policy` | R21 |
| Cookies : `HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`, préfixe `__Host-` | R26–R33 |
| CORS : réflexion d'une Origin arbitraire / `null`, avec credentials | R40 |
| SRI et `crossorigin` sur les ressources internes et tierces | R11, R12, R43 |
| `target` sans `rel="noopener"`, `window.open` | R45 |
| `Cross-Origin-Opener-Policy` | R46 |
| iframes sans `sandbox` ou sandbox inefficace | R50, R51 |
| JSON-P | R58 |
| JS : `eval`, `new Function`, `setTimeout("…")`, `innerHTML`, `document.write`, `openDatabase`, `localStorage`, `indexedDB`, `XMLHttpRequest`, `postMessage(…, '*')`, écouteurs `message`, `document.domain`, `'use strict'` | R4, R9, R10, R23–R25, R44, R47, R54, R55, R57 |
| Bibliothèques obsolètes (jQuery, AngularJS, Bootstrap, Lodash, Moment) | R61, R62 |
| Indices de profil de développement (versions exposées, source maps, traces) | R60 |

Les recommandations qui relèvent de la revue de code ou de l'organisation
(R3, R5, R7, R8, R22, R35–R39, R41, R42, R48–R50, R53, R56, R59–R63…) sont listées
comme **MANUEL**, avec le point de contrôle à réaliser.

## Limites

L'analyse du JavaScript est statique et heuristique (pas d'exécution) : les
applications générées côté client (SPA) ou le code minifié peuvent produire des
faux positifs ou négatifs. Le score n'agrège que les contrôles automatisés ; il
ne remplace pas un audit complet (ex. `testssl.sh` pour TLS, revue de code).
