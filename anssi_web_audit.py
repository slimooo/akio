#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
anssi_web_audit.py — Audit de sécurité côté navigateur d'une application web
selon le guide ANSSI-PA-009 v2.0 (28/04/2021) :
« Recommandations pour la mise en œuvre d'un site web : maîtriser les
standards de sécurité côté navigateur ».

Le script effectue des vérifications non intrusives (requêtes HTTP(S)
classiques, poignées de main TLS, analyse statique du HTML et du JavaScript
servis) et associe chaque constat à une recommandation Rxx du guide.
Les recommandations non vérifiables automatiquement sont listées comme
« MANUEL » avec le point de contrôle à réaliser.

N'utilisez ce script que sur des applications que vous êtes autorisé à tester.

Usage :
    python3 anssi_web_audit.py https://exemple.fr
    python3 anssi_web_audit.py https://exemple.fr/login --cookie "session=..." \
        --json rapport.json --html rapport.html

Dépendances : bibliothèque standard Python >= 3.8 uniquement.
"""

import argparse
import datetime as dt
import html
import http.client
import json
import re
import socket
import ssl
import sys
import warnings
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

warnings.filterwarnings("ignore", category=DeprecationWarning)

VERSION = "1.0.0"
USER_AGENT = f"anssi-web-audit/{VERSION} (+ANSSI-PA-009)"
GUIDE_URL = ("https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-"
             "recommandations_mise_en_oeuvre_site_web_maitriser_standards_"
             "securite_cote_navigateur-v2.0.pdf")

# Statuts
PASS, FAIL, WARN, INFO, MANUAL, NA = "OK", "ÉCHEC", "ATTENTION", "INFO", "MANUEL", "N/A"
STATUS_ORDER = [FAIL, WARN, PASS, INFO, MANUAL, NA]

# Intitulés des recommandations du guide (liste p. 68-69)
RECOS: Dict[str, str] = {
    "R1": "Mettre en œuvre TLS à l'état de l'art",
    "R2": "Mettre en œuvre HSTS",
    "R3": "Surveiller les CT logs",
    "R4": "Utiliser l'API DOM à bon escient",
    "R5": "Dissocier clairement la composition des pages web",
    "R6": "Expliciter la nature d'une ressource avec l'en-tête Content-Type",
    "R7": "Vérifier l'échappement des contenus inclus",
    "R8": "Vérifier la conformité des données issues de sources externes",
    "R9": "Proscrire l'usage de la fonction eval()",
    "R10": "Proscrire l'usage de constructions basées sur l'évaluation de code",
    "R11": "Contrôler l'intégrité des contenus internes",
    "R12": "Contrôler l'intégrité des contenus tiers",
    "R13": "Restreindre les contenus aux ressources fiables",
    "R14": "Mettre en œuvre CSP par en-tête HTTP",
    "R15": "Interdire des contenus inline",
    "R16": "Définir la directive default-src",
    "R17": "Utiliser CSP contre le clickjacking",
    "R18": "Utiliser X-Frame-Options contre le clickjacking",
    "R19": "Étudier les risques liés à la collecte de rapports CSP",
    "R20": "Réduire l'impact des requêtes silencieuses via CSP",
    "R21": "Définir la stratégie de construction de l'en-tête Referer",
    "R22": "Modifier ponctuellement l'en-tête Referer",
    "R23": "Ne pas stocker d'informations sensibles dans les bases de données locales",
    "R24": "Ne pas stocker d'informations sensibles dans IndexedDB",
    "R25": "Proscrire l'usage de l'API Web SQL Database",
    "R26": "Ne pas stocker d'informations sensibles dans les cookies",
    "R27": "Cloisonner les sessions au moyen de noms de domaine distincts",
    "R28": "Définir le path d'un cookie",
    "R29": "Maîtriser l'accès aux cookies en JavaScript",
    "R30": "Proscrire l'accès en JavaScript à un cookie de session",
    "R31": "Limiter le transit des cookies aux flux sécurisés",
    "R32": "Définir une stratégie stricte d'envoi des cookies en cross-site",
    "R33": "Définir une stratégie stricte d'envoi des cookies de session en cross-site",
    "R34": "Encoder les réponses XMLHttpRequest",
    "R35": "Choisir une API selon sa méthode HTTP",
    "R36": "Utiliser XHR avec la méthode POST (PUT de préférence)",
    "R37": "Compléter la mise en œuvre de XHR par une configuration CSP",
    "R38": "Protéger les appels XHR par un contrôle anti-CSRF",
    "R39": "Mettre en œuvre un preflight lors des appels CORS",
    "R40": "Vérifier la valeur de l'Origin lors de la réception d'une requête CORS",
    "R41": "Cloisonner les services web au moyen de noms de domaines distincts",
    "R42": "Éviter l'usage de bibliothèques publiques effectuant des appels CORS",
    "R43": "Anonymiser le chargement des ressources en cross-origin",
    "R44": "Préférer l'utilisation de l'API Fetch à XMLHttpRequest",
    "R45": "Sécuriser l'ouverture de nouvelles fenêtres",
    "R46": "Définir une stratégie d'ouverture en cross-origin",
    "R47": "Utiliser le mode strict",
    "R48": "Isoler les traitements par Web Workers",
    "R49": "Formaliser les échanges en utilisant l'API de Message (Workers)",
    "R50": "Cloisonner les traitements dans des iframes",
    "R51": "Cloisonner les traitements avec une sandbox",
    "R52": "Favoriser la déclaration de sandbox via CSP",
    "R53": "Formaliser les échanges en utilisant l'API de Message (iframes)",
    "R54": "Définir l'Origin lors de l'utilisation de l'API de Message",
    "R55": "Contrôler l'Origin lors de l'utilisation de l'API de Message",
    "R56": "Compléter la déclaration d'une API de messages par la définition d'une CSP",
    "R57": "Proscrire l'écriture de document.domain",
    "R58": "Proscrire l'usage de JSON-P",
    "R59": "Définir des profils de déploiement spécifiques aux contextes",
    "R60": "Empêcher le déploiement d'un profil non adapté au contexte",
    "R61": "Limiter les composants logiciels tiers",
    "R62": "Maintenir à jour les composants logiciels tiers utilisés",
    "R63": "Ne pas modifier le cœur des composants logiciels tiers utilisés",
}

# Points de contrôle pour les recommandations non automatisables
MANUAL_CHECKS: Dict[str, str] = {
    "R3": "Surveiller les journaux Certificate Transparency du domaine "
          "(ex. https://crt.sh/?q={host}) pour détecter des certificats illégitimes.",
    "R5": "Vérifier que HTML, CSS et JavaScript sont servis dans des ressources distinctes "
          "(pas de gabarits mélangeant données et code).",
    "R7": "Vérifier par revue de code / tests que toute donnée incluse dans une page est "
          "échappée selon son contexte (HTML, attribut, JS, URL, CSS).",
    "R8": "Vérifier la validation des données provenant de sources externes (API, "
          "postMessage, stockage local, URL).",
    "R22": "Vérifier que les liens sensibles utilisent referrerpolicy/rel=noreferrer si besoin.",
    "R23": "Vérifier qu'aucune donnée sensible (jeton, donnée personnelle) n'est stockée dans "
           "localStorage/sessionStorage (DevTools > Application).",
    "R24": "Vérifier qu'aucune donnée sensible n'est stockée dans IndexedDB.",
    "R26": "Vérifier que les cookies ne contiennent pas d'informations sensibles en clair.",
    "R34": "Vérifier que les réponses aux appels XHR/fetch sont correctement encodées "
           "(JSON avec Content-Type application/json, pas d'HTML).",
    "R35": "Vérifier que les actions modifiant l'état n'utilisent pas la méthode GET.",
    "R36": "Vérifier que les appels XHR modifiant l'état utilisent POST ou PUT.",
    "R38": "Vérifier la présence d'un jeton anti-CSRF (ou d'un en-tête personnalisé) sur les "
           "requêtes modifiant l'état.",
    "R39": "Pour les appels CORS sensibles, forcer un preflight (en-tête non standard) "
           "et vérifier sa présence côté serveur.",
    "R41": "Vérifier que les services web exposés en CORS sont sur des domaines distincts "
           "de l'application.",
    "R42": "Vérifier l'absence de bibliothèques tierces effectuant des appels CORS "
           "non maîtrisés.",
    "R48": "Envisager d'isoler les traitements de données non fiables dans des Web Workers.",
    "R49": "Vérifier que les échanges avec les Workers passent par postMessage avec un "
           "format formalisé et validé.",
    "R50": "Envisager d'isoler les contenus non fiables dans des iframes.",
    "R53": "Vérifier que les échanges avec les iframes passent par postMessage avec un "
           "format formalisé et validé.",
    "R56": "Vérifier que l'usage de postMessage est complété par une CSP (frame-src, "
           "child-src, frame-ancestors).",
    "R59": "Vérifier l'existence de profils de déploiement (dev/recette/prod) distincts.",
    "R60": "Vérifier qu'un profil de développement ne peut pas être déployé en production "
           "(mode debug, source maps, CSP relâchée…).",
    "R61": "Inventorier et limiter les composants tiers au strict nécessaire.",
    "R62": "Vérifier que les composants tiers sont à jour (ex. npm audit, retire.js, "
           "Dependabot).",
    "R63": "Vérifier que le cœur des composants tiers n'a pas été modifié "
           "(comparaison avec les sources officielles).",
}

SESSION_COOKIE_RE = re.compile(
    r"(sess|sid|auth|token|jwt|login|connect|remember|csrf|xsrf|jsession|"
    r"phpsessid|asp\.net|laravel|_session)", re.I)

# Motifs JavaScript à rechercher (analyse statique heuristique)
JS_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    ("R9", "Appel à eval()", re.compile(r"(?<![\w$.])eval\s*\(")),
    ("R10", "Constructeur Function()", re.compile(r"\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(\s*['\"`]")),
    ("R10", "setTimeout/setInterval avec chaîne",
     re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]")),
    ("R4", "innerHTML / outerHTML", re.compile(r"\.(?:inner|outer)HTML\s*\+?=(?!=)")),
    ("R4", "document.write / writeln", re.compile(r"\bdocument\.write(?:ln)?\s*\(")),
    ("R4", "insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(")),
    ("R25", "API Web SQL (openDatabase)", re.compile(r"\bopenDatabase\s*\(")),
    ("R23", "Usage de localStorage/sessionStorage", re.compile(r"\b(?:local|session)Storage\b")),
    ("R24", "Usage d'IndexedDB", re.compile(r"\bindexedDB\s*\.\s*open\s*\(")),
    ("R44", "Usage de XMLHttpRequest", re.compile(r"\bnew\s+XMLHttpRequest\s*\(")),
    ("R45", "window.open sans noopener", re.compile(r"\bwindow\.open\s*\(([^)]*)\)")),
    ("R54", "postMessage avec cible '*'", re.compile(r"\.postMessage\s*\([^;]*?,\s*['\"]\*['\"]")),
    ("R55", "Écouteur 'message'", re.compile(r"addEventListener\s*\(\s*['\"]message['\"]|\bonmessage\s*=")),
    ("R57", "Écriture de document.domain", re.compile(r"\bdocument\.domain\s*=(?!=)")),
    ("R47", "Directive 'use strict'", re.compile(r"['\"]use strict['\"]")),
]

# Bibliothèques connues : (nom, regex de version, version minimale conseillée)
KNOWN_LIBS = [
    ("jQuery", re.compile(r"jQuery (?:JavaScript Library )?v?(\d+\.\d+\.\d+)|jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I), "3.5.0"),
    ("AngularJS", re.compile(r"AngularJS v(1\.\d+\.\d+)|angular[.-](1\.\d+\.\d+)", re.I), "99"),  # fin de vie
    ("Bootstrap", re.compile(r"Bootstrap v(\d+\.\d+\.\d+)|bootstrap[.-](\d+\.\d+\.\d+)", re.I), "4.3.1"),
    ("Lodash", re.compile(r"lodash (?:lodash\.com )?v?(\d+\.\d+\.\d+)|lodash[.-](\d+\.\d+\.\d+)", re.I), "4.17.21"),
    ("Moment.js", re.compile(r"moment[.-](\d+\.\d+\.\d+)|//! version : (\d+\.\d+\.\d+)", re.I), "2.29.4"),
]


@dataclass
class Finding:
    reco: str
    status: str
    title: str
    detail: str = ""
    evidence: List[str] = field(default_factory=list)


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: List[Tuple[str, str]]
    body: bytes

    def get(self, name: str) -> Optional[str]:
        vals = self.get_all(name)
        return ", ".join(vals) if vals else None

    def get_all(self, name: str) -> List[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    @property
    def text(self) -> str:
        ctype = self.get("Content-Type") or ""
        m = re.search(r"charset=([\w-]+)", ctype, re.I)
        enc = m.group(1) if m else "utf-8"
        try:
            return self.body.decode(enc, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Réseau
# ---------------------------------------------------------------------------

class Http:
    def __init__(self, timeout: float, insecure: bool, extra_headers: Dict[str, str],
                 max_body: int = 3_000_000):
        self.timeout = timeout
        self.insecure = insecure
        self.extra_headers = extra_headers
        self.max_body = max_body

    def _ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if self.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def request(self, url: str, method: str = "GET",
                headers: Optional[Dict[str, str]] = None) -> Response:
        u = urlparse(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(u.hostname, port, timeout=self.timeout,
                                               context=self._ctx())
        else:
            conn = http.client.HTTPConnection(u.hostname, port, timeout=self.timeout)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        h = {"User-Agent": USER_AGENT, "Accept": "*/*", "Accept-Encoding": "identity"}
        h.update(self.extra_headers)
        if headers:
            h.update(headers)
        try:
            conn.request(method, path, headers=h)
            r = conn.getresponse()
            body = r.read(self.max_body) if method != "HEAD" else b""
            return Response(url, r.status, r.reason, r.getheaders(), body)
        finally:
            conn.close()

    def get_follow(self, url: str, max_redirects: int = 8) -> Tuple[Response, List[Response]]:
        chain: List[Response] = []
        for _ in range(max_redirects + 1):
            r = self.request(url)
            chain.append(r)
            loc = r.get("Location")
            if r.status in (301, 302, 303, 307, 308) and loc:
                url = urljoin(url, loc)
                continue
            return r, chain
        return chain[-1], chain


def tls_probe(host: str, port: int, version: "ssl.TLSVersion", timeout: float) -> Optional[bool]:
    """True si le serveur accepte exactement cette version, False sinon,
    None si la version n'est pas testable avec l'OpenSSL local."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError, AttributeError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return ss.version() is not None
    except ssl.SSLError as e:
        msg = str(e).lower()
        if "no protocols available" in msg:
            return None
        return False
    except (OSError, socket.timeout):
        return False


# ---------------------------------------------------------------------------
# Analyse HTML
# ---------------------------------------------------------------------------

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: List[Dict[str, Optional[str]]] = []
        self.inline_scripts: List[str] = []
        self.styles: List[Dict[str, Optional[str]]] = []
        self.inline_styles = 0
        self.inline_handlers: List[str] = []
        self.links_blank: List[Dict[str, Optional[str]]] = []
        self.iframes: List[Dict[str, Optional[str]]] = []
        self.meta_csp: List[str] = []
        self.meta_referrer: Optional[str] = None
        self.forms: List[Dict[str, Optional[str]]] = []
        self.js_urls: List[str] = []
        self._in_script = False
        self._script_buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): v for k, v in attrs}
        for k, v in a.items():
            if k.startswith("on"):
                self.inline_handlers.append(f"<{tag} {k}=…>")
            if k in ("href", "src", "action") and v and v.strip().lower().startswith("javascript:"):
                self.js_urls.append(f"<{tag} {k}=\"{v[:60]}\">")
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a)
            else:
                t = (a.get("type") or "").lower()
                if t in ("", "text/javascript", "module", "application/javascript"):
                    self._in_script = True
                    self._script_buf = []
        elif tag == "link" and "stylesheet" in (a.get("rel") or "").lower() and a.get("href"):
            self.styles.append(a)
        elif tag == "style":
            self.inline_styles += 1
        elif tag in ("a", "area", "form") and (a.get("target") or "").lower() not in ("", "_self", "_parent", "_top"):
            self.links_blank.append({"tag": tag, **a})
        elif tag == "iframe":
            self.iframes.append(a)
        elif tag == "meta":
            he = (a.get("http-equiv") or "").lower()
            if he == "content-security-policy" and a.get("content"):
                self.meta_csp.append(a["content"])
            if (a.get("name") or "").lower() == "referrer":
                self.meta_referrer = a.get("content")
        if tag == "form":
            self.forms.append(a)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._script_buf))
            self._in_script = False

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)


def parse_csp(value: str) -> Dict[str, List[str]]:
    d: Dict[str, List[str]] = {}
    for part in value.split(";"):
        toks = part.strip().split()
        if toks:
            name = toks[0].lower()
            if name not in d:  # la première occurrence prévaut
                d[name] = [t for t in toks[1:]]
    return d


def same_site(u1: str, u2: str) -> bool:
    h1, h2 = urlparse(u1).hostname or "", urlparse(u2).hostname or ""
    return h1 == h2


def vtuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

class Auditor:
    def __init__(self, url: str, args):
        self.url = url
        self.args = args
        self.findings: List[Finding] = []
        extra = {}
        if args.cookie:
            extra["Cookie"] = args.cookie
        for h in args.header or []:
            k, _, v = h.partition(":")
            extra[k.strip()] = v.strip()
        self.http = Http(args.timeout, args.insecure, extra)
        self.final: Optional[Response] = None
        self.page: Optional[PageParser] = None
        self.csp: Dict[str, List[str]] = {}
        self.csp_source = None

    def add(self, reco, status, title, detail="", evidence=None):
        self.findings.append(Finding(reco, status, title, detail, list(evidence or [])[:15]))

    def log(self, msg):
        if not self.args.quiet:
            print(f"  … {msg}", file=sys.stderr)

    # --- Transport -------------------------------------------------------
    def check_transport(self):
        u = urlparse(self.url)
        host = u.hostname
        if u.scheme != "https":
            self.add("R1", FAIL, "L'URL auditée n'utilise pas HTTPS",
                     "Tout site doit être servi exclusivement en HTTPS.")
        # Redirection HTTP -> HTTPS
        self.log("redirection HTTP → HTTPS")
        http_url = f"http://{host}{':' + str(u.port) if u.port and u.scheme == 'http' else ''}{u.path or '/'}"
        try:
            r = self.http.request(http_url)
            loc = r.get("Location") or ""
            if r.status in (301, 302, 307, 308) and loc.lower().startswith("https://"):
                st = PASS if r.status in (301, 308) else WARN
                self.add("R1", st, "Redirection HTTP vers HTTPS",
                         f"HTTP {r.status} → {loc}" + ("" if st == PASS else
                         " (préférer une redirection permanente 301/308)"))
            elif u.scheme == "https":
                self.add("R1", FAIL, "Le site répond en HTTP sans rediriger vers HTTPS",
                         f"HTTP {r.status} sur {http_url}")
        except (OSError, http.client.HTTPException) as e:
            self.add("R1", PASS if u.scheme == "https" else INFO,
                     "Port HTTP (80) fermé ou injoignable", str(e))

        if u.scheme != "https":
            return
        port = u.port or 443
        # Certificat et version négociée
        self.log("poignée de main TLS")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.args.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    ver, cipher = ss.version(), ss.cipher()
            exp = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days = (exp - dt.datetime.utcnow()).days
            self.add("R1", PASS if days > 30 else WARN, "Certificat valide pour le nom d'hôte",
                     f"Expire le {exp:%Y-%m-%d} ({days} jours) — négocié : {ver} / {cipher[0]}")
        except ssl.SSLCertVerificationError as e:
            self.add("R1", FAIL, "Certificat invalide", e.verify_message or str(e))
        except (OSError, ssl.SSLError) as e:
            self.add("R1", FAIL, "Échec de la poignée de main TLS", str(e))
            return

        # Versions de protocole (guide ANSSI TLS : TLS 1.2 minimum, 1.3 conseillé)
        self.log("versions TLS acceptées")
        probes = {}
        for name in ("TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"):
            ver = getattr(ssl.TLSVersion, name, None)
            probes[name] = tls_probe(host, port, ver, self.args.timeout) if ver else None
        label = {"TLSv1": "TLS 1.0", "TLSv1_1": "TLS 1.1", "TLSv1_2": "TLS 1.2", "TLSv1_3": "TLS 1.3"}
        ev = [f"{label[k]} : {'accepté' if v else 'refusé' if v is False else 'non testable localement'}"
              for k, v in probes.items()]
        old = [label[k] for k in ("TLSv1", "TLSv1_1") if probes[k]]
        if old:
            self.add("R1", FAIL, "Versions obsolètes de TLS acceptées", ", ".join(old), ev)
        elif not probes["TLSv1_3"] and not probes["TLSv1_2"]:
            self.add("R1", WARN, "Versions TLS non déterminées", "", ev)
        else:
            self.add("R1", PASS if probes["TLSv1_3"] else WARN,
                     "Versions de TLS", "TLS 1.3 supporté" if probes["TLSv1_3"]
                     else "TLS 1.3 non supporté (recommandé par le guide ANSSI TLS)", ev)
        self.add("R1", MANUAL, "Suites cryptographiques et paramètres TLS",
                 "Compléter par un audit détaillé (ex. testssl.sh, SSL Labs) au regard du guide "
                 "ANSSI-PA-035 « Recommandations de sécurité relatives à TLS ».")

    # --- Page principale ---------------------------------------------------
    def fetch_page(self) -> bool:
        self.log(f"récupération de {self.url}")
        try:
            self.final, chain = self.http.get_follow(self.url)
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            self.add("R1", FAIL, "Impossible de récupérer la page", str(e))
            return False
        if len(chain) > 1:
            self.add("R1", INFO, "Chaîne de redirections",
                     " → ".join(f"{r.status} {r.url}" for r in chain))
            for r in chain[:-1]:
                loc = urljoin(r.url, r.get("Location") or "")
                if r.url.startswith("https://") and loc.startswith("http://"):
                    self.add("R1", FAIL, "Redirection de HTTPS vers HTTP", f"{r.url} → {loc}")
        self.page = PageParser()
        ctype = (self.final.get("Content-Type") or "").lower()
        if "html" in ctype or not ctype:
            try:
                self.page.feed(self.final.text)
            except Exception:  # HTML très malformé
                pass
        return True

    # --- En-têtes ----------------------------------------------------------
    def check_hsts(self):
        r = self.final
        if not r.url.startswith("https://"):
            self.add("R2", FAIL, "HSTS impossible sans HTTPS")
            return
        v = r.get("Strict-Transport-Security")
        if not v:
            self.add("R2", FAIL, "En-tête Strict-Transport-Security absent",
                     "Exemple : Strict-Transport-Security: max-age=31536000; includeSubDomains")
            return
        m = re.search(r"max-age\s*=\s*\"?(\d+)", v, re.I)
        age = int(m.group(1)) if m else 0
        issues = []
        if age < 31536000:
            issues.append(f"max-age={age} inférieur à 1 an (31536000)")
        if "includesubdomains" not in v.lower():
            issues.append("includeSubDomains absent")
        self.add("R2", WARN if issues else PASS, "HSTS", "; ".join(issues) or v, [v])

    def check_content_type(self):
        r = self.final
        ct = r.get("Content-Type")
        if not ct:
            self.add("R6", FAIL, "En-tête Content-Type absent")
        elif "html" in ct.lower() and "charset" not in ct.lower():
            self.add("R6", WARN, "Content-Type sans jeu de caractères", ct)
        else:
            self.add("R6", PASS, "Content-Type explicite", ct)
        xcto = (r.get("X-Content-Type-Options") or "").lower()
        self.add("R6", PASS if "nosniff" in xcto else WARN, "X-Content-Type-Options: nosniff",
                 "présent" if "nosniff" in xcto else
                 "absent : le navigateur peut deviner le type (MIME sniffing)")

    def check_csp(self):
        r = self.final
        hdr = r.get_all("Content-Security-Policy")
        ro = r.get("Content-Security-Policy-Report-Only")
        metas = self.page.meta_csp if self.page else []
        if hdr:
            self.csp = parse_csp(hdr[0])
            self.csp_source = "en-tête"
            self.add("R14", PASS, "CSP définie par en-tête HTTP", "", hdr)
        elif metas:
            self.csp = parse_csp(metas[0])
            self.csp_source = "meta"
            self.add("R14", WARN, "CSP définie uniquement par balise <meta>",
                     "Recommandation dégradée (R14-) : privilégier l'en-tête HTTP ; "
                     "frame-ancestors, report-uri et sandbox sont ignorés en <meta>.", metas)
        else:
            self.add("R14", FAIL, "Aucune Content-Security-Policy",
                     "Report-Only présent (non bloquant) : " + ro if ro else "")
            for rid in ("R13", "R15", "R16", "R17", "R20"):
                self.add(rid, FAIL, "Non satisfait : aucune CSP")
            return
        c = self.csp
        # R13 / R20 : restriction des sources
        wild = []
        for d, srcs in c.items():
            if d.endswith("-src") or d == "default-src":
                for s in srcs:
                    if s in ("*", "http:", "https:") or s.startswith("http://"):
                        wild.append(f"{d} {s}")
        self.add("R13", WARN if wild else PASS, "Sources de contenu restreintes",
                 "Sources trop permissives : " + ", ".join(wild) if wild else
                 "Aucune source générique (*, https:, http:)")
        # R15
        bad = []
        for d, srcs in c.items():
            if d in ("script-src", "script-src-elem", "script-src-attr", "style-src",
                     "style-src-elem", "style-src-attr", "default-src", "img-src",
                     "object-src", "frame-src", "child-src", "connect-src", "font-src",
                     "media-src", "worker-src"):
                for s in srcs:
                    if s.lower() in ("'unsafe-inline'", "'unsafe-eval'", "data:",
                                     "'unsafe-hashes'", "'wasm-unsafe-eval'"):
                        bad.append(f"{d} {s}")
        # 'unsafe-inline' est ignoré si un nonce/hash est présent (CSP niveau 2+)
        self.add("R15", FAIL if bad else PASS, "Contenus inline / évaluation de code interdits",
                 "Mots-clés proscrits : " + ", ".join(bad) if bad else
                 "Aucun 'unsafe-inline', 'unsafe-eval' ni data:")
        # R16
        ds = c.get("default-src")
        if ds is None:
            self.add("R16", FAIL, "Directive default-src absente")
        elif ds == ["*"] or "*" in ds:
            self.add("R16", FAIL, "default-src positionnée à *", " ".join(ds))
        else:
            self.add("R16", PASS, "default-src définie", "default-src " + " ".join(ds))
        # R17
        fa = c.get("frame-ancestors")
        if fa is None or self.csp_source == "meta":
            self.add("R17", FAIL, "frame-ancestors absente de la CSP (en-tête)",
                     "Exemple : frame-ancestors 'none' ou 'self'")
        elif "*" in fa or "https:" in fa:
            self.add("R17", FAIL, "frame-ancestors trop permissive", " ".join(fa))
        else:
            self.add("R17", PASS, "frame-ancestors définie", " ".join(fa))
        # R19
        rep = c.get("report-uri") or c.get("report-to")
        if rep:
            self.add("R19", MANUAL, "Collecte de rapports CSP configurée",
                     f"Point de collecte : {' '.join(rep)} — étudier les risques (données "
                     "personnelles, déni de service, exposition du point de collecte).")
        else:
            self.add("R19", INFO, "Pas de collecte de rapports CSP (report-uri / report-to)")
        # R20
        cs = c.get("connect-src", c.get("default-src"))
        if cs is None or any(s in ("*", "https:", "http:") for s in cs):
            self.add("R20", WARN, "Origins atteignables non restreintes",
                     "Définir connect-src / default-src avec une liste d'Origins minimale.")
        else:
            self.add("R20", PASS, "Origins atteignables restreintes",
                     ("connect-src " if "connect-src" in c else "default-src ") + " ".join(cs))
        # R37 : CSP et XHR
        self.add("R37", PASS if "connect-src" in c else INFO,
                 "Directive connect-src" + (" définie" if "connect-src" in c else " absente"),
                 "" if "connect-src" in c else "Les appels XHR/fetch sont régis par default-src.")
        # R52 : sandbox via CSP
        if "sandbox" in c:
            self.add("R52", PASS, "Directive CSP sandbox présente", " ".join(c["sandbox"]))
        # Trusted Types (bonus R4)
        if "require-trusted-types-for" in c:
            self.add("R4", PASS, "Trusted Types exigés par la CSP",
                     " ".join(c["require-trusted-types-for"]))

    def check_xfo(self):
        v = (self.final.get("X-Frame-Options") or "").strip().lower()
        if v in ("deny", "sameorigin"):
            self.add("R18", PASS, "X-Frame-Options strict", v.upper())
        elif v:
            self.add("R18", WARN, "X-Frame-Options non strict ou obsolète", v)
        else:
            self.add("R18", FAIL, "En-tête X-Frame-Options absent",
                     "Défense en profondeur : X-Frame-Options: DENY ou SAMEORIGIN")

    def check_referrer(self):
        v = self.final.get("Referrer-Policy") or (self.page.meta_referrer if self.page else None)
        if not v:
            self.add("R21", FAIL, "Referrer-Policy absente",
                     "La stratégie par défaut ne doit pas être conservée ; ex. "
                     "Referrer-Policy: strict-origin-when-cross-origin ou no-referrer")
            return
        last = v.split(",")[-1].strip().lower()  # la dernière valeur connue prévaut
        if last in ("unsafe-url", "no-referrer-when-downgrade", "origin-when-cross-origin"):
            self.add("R21", FAIL, "Referrer-Policy trop permissive", v)
        else:
            self.add("R21", PASS, "Referrer-Policy définie", v)

    def check_coop(self):
        v = (self.final.get("Cross-Origin-Opener-Policy") or "").strip().lower()
        if v == "same-origin":
            self.add("R46", PASS, "Cross-Origin-Opener-Policy: same-origin")
        elif v:
            self.add("R46", WARN, "Cross-Origin-Opener-Policy non stricte", v)
        else:
            self.add("R46", FAIL, "Cross-Origin-Opener-Policy absente",
                     "Recommandé : Cross-Origin-Opener-Policy: same-origin")

    # --- Cookies -----------------------------------------------------------
    def check_cookies(self):
        # http.client renvoie un couple (nom, valeur) par en-tête Set-Cookie
        cookies = [c for c in self.final.get_all("Set-Cookie") if c.strip()]
        if not cookies:
            self.add("R29", NA, "Aucun cookie déposé sur cette page",
                     "Relancer sur une page authentifiée (--cookie) ou de connexion.")
            return
        host = urlparse(self.final.url).hostname or ""
        https = self.final.url.startswith("https://")
        for raw in cookies:
            name = raw.split("=", 1)[0].strip()
            attrs = {}
            for p in raw.split(";")[1:]:
                k, _, v = p.strip().partition("=")
                attrs[k.strip().lower()] = v.strip()
            is_session = bool(SESSION_COOKIE_RE.search(name)) or name.startswith("__Host-")
            is_session = is_session and not re.search(r"csrf|xsrf", name, re.I)
            tag = f"cookie « {name} »" + (" (session présumée)" if is_session else "")
            # R27 / R28
            if "domain" in attrs:
                self.add("R27", WARN, f"{tag} : attribut Domain défini",
                         f"Domain={attrs['domain']} — le cookie est partagé avec les sous-domaines. "
                         "Préférer l'omettre (cookie limité à l'hôte, préfixe __Host-).")
            path = attrs.get("path")
            if path is None:
                self.add("R28", WARN, f"{tag} : attribut Path non défini")
            else:
                self.add("R28", PASS if path != "/" or name.startswith("__Host-") else INFO,
                         f"{tag} : Path={path}")
            # R29 / R30
            if "httponly" not in attrs:
                self.add("R30" if is_session else "R29", FAIL if is_session else WARN,
                         f"{tag} : HttpOnly absent",
                         "Accessible en JavaScript (vol possible via XSS).")
            else:
                self.add("R30" if is_session else "R29", PASS, f"{tag} : HttpOnly")
            # R31
            if "secure" not in attrs:
                self.add("R31", FAIL if https else WARN, f"{tag} : Secure absent")
            else:
                self.add("R31", PASS, f"{tag} : Secure")
            # R32 / R33
            ss = attrs.get("samesite", "").lower()
            rid = "R33" if is_session else "R32"
            if not ss:
                self.add(rid, FAIL if is_session else WARN, f"{tag} : SameSite non défini")
            elif ss == "none":
                self.add(rid, FAIL, f"{tag} : SameSite=None")
            elif ss == "lax":
                self.add(rid, PASS if not is_session else WARN, f"{tag} : SameSite=Lax",
                         "" if not is_session else "Strict recommandé si possible")
            else:
                self.add(rid, PASS, f"{tag} : SameSite={ss.capitalize()}")
            # préfixes
            if name.startswith("__Host-") and ("domain" in attrs or path != "/" or "secure" not in attrs):
                self.add("R27", FAIL, f"{tag} : préfixe __Host- mal utilisé")
            # R26 : heuristique sur la valeur
            val = raw.split(";", 1)[0].split("=", 1)[-1]
            if re.search(r"@|password|passwd|mdp|admin=|role=|\buser(name)?=", val, re.I):
                self.add("R26", WARN, f"{tag} : valeur semblant contenir une donnée sensible",
                         val[:80])

    # --- CORS --------------------------------------------------------------
    def check_cors(self):
        self.log("test CORS (Origin arbitraire)")
        results = []
        for origin in ("https://anssi-audit-evil.example", "null"):
            try:
                r = self.http.request(self.final.url, headers={"Origin": origin})
            except (OSError, http.client.HTTPException, ssl.SSLError):
                continue
            acao = r.get("Access-Control-Allow-Origin")
            acac = (r.get("Access-Control-Allow-Credentials") or "").lower() == "true"
            results.append((origin, acao, acac))
        bad = [(o, a, c) for o, a, c in results if a and (a == o or a == "*")]
        if not results:
            self.add("R40", INFO, "Test CORS non réalisé")
        elif any(a == o and c for o, a, c in bad):
            self.add("R40", FAIL, "L'Origin est reflétée avec Access-Control-Allow-Credentials",
                     "Toute origine peut lire les réponses authentifiées (CSRF/vol de données).",
                     [f"Origin: {o} → ACAO: {a}, ACAC: {c}" for o, a, c in bad])
        elif any(a == o for o, a, c in bad):
            self.add("R40", WARN, "L'Origin est reflétée sans contrôle",
                     "", [f"Origin: {o} → ACAO: {a}" for o, a, c in bad])
        elif any(a == "*" for o, a, c in bad):
            self.add("R40", WARN, "Access-Control-Allow-Origin: *",
                     "Acceptable uniquement pour des ressources publiques.")
        else:
            self.add("R40", PASS, "Pas de réflexion d'une Origin arbitraire",
                     "(vérifier aussi les points d'API : --extra-url)")

    # --- HTML --------------------------------------------------------------
    def check_html(self):
        p = self.page
        base = self.final.url
        # R11/R12/R43 : SRI et crossorigin
        ext_no_sri, int_no_sri, ext_no_co = [], [], []
        for el in p.scripts + p.styles:
            src = el.get("src") or el.get("href")
            full = urljoin(base, src)
            if urlparse(full).scheme not in ("http", "https"):
                continue
            third = not same_site(full, base)
            if third:
                if not el.get("integrity"):
                    ext_no_sri.append(full)
                if el.get("crossorigin") is None or el.get("crossorigin") == "use-credentials":
                    ext_no_co.append(full)
            elif not el.get("integrity"):
                int_no_sri.append(full)
            if full.startswith("http://") and base.startswith("https://"):
                self.add("R1", FAIL, "Contenu mixte (ressource chargée en HTTP)", full)
        n_ext = sum(1 for el in p.scripts + p.styles
                    if not same_site(urljoin(base, el.get("src") or el.get("href")), base))
        if n_ext == 0:
            self.add("R12", NA, "Aucun script/feuille de style tiers")
        else:
            self.add("R12", FAIL if ext_no_sri else PASS,
                     "Intégrité (SRI) des contenus tiers",
                     f"{len(ext_no_sri)}/{n_ext} ressource(s) tierce(s) sans attribut integrity",
                     ext_no_sri)
            self.add("R43", WARN if ext_no_co else PASS,
                     "Chargement anonyme des ressources cross-origin",
                     f"{len(ext_no_co)} ressource(s) sans crossorigin=\"anonymous\"", ext_no_co)
        self.add("R11", INFO if int_no_sri else PASS, "Intégrité (SRI) des contenus internes",
                 f"{len(int_no_sri)} ressource(s) interne(s) sans integrity", int_no_sri)
        # R15 : contenus inline dans le HTML
        inl = len([s for s in p.inline_scripts if s.strip()])
        if inl or p.inline_handlers or p.inline_styles or p.js_urls:
            self.add("R15", WARN, "Contenus inline présents dans la page",
                     f"{inl} script(s) inline, {len(p.inline_handlers)} gestionnaire(s) "
                     f"d'événement (on*), {p.inline_styles} bloc(s) <style>, "
                     f"{len(p.js_urls)} URL javascript:",
                     p.inline_handlers[:5] + p.js_urls[:5])
        # R45 : target sans noopener
        unsafe = [f"<{l['tag']} href=\"{(l.get('href') or l.get('action') or '')[:80]}\">"
                  for l in p.links_blank
                  if not re.search(r"\bno(opener|referrer)\b", l.get("rel") or "", re.I)]
        if p.links_blank:
            self.add("R45", WARN if unsafe else PASS, "Liens ouvrant une nouvelle fenêtre",
                     f"{len(unsafe)}/{len(p.links_blank)} sans rel=\"noopener\"", unsafe)
        # R50/R51 : iframes
        if p.iframes:
            nosb = [i.get("src") or "(sans src)" for i in p.iframes if i.get("sandbox") is None]
            self.add("R51", WARN if nosb else PASS, "Iframes cloisonnées par sandbox",
                     f"{len(nosb)}/{len(p.iframes)} iframe(s) sans attribut sandbox", nosb)
            weak = [i.get("src") for i in p.iframes if i.get("sandbox") is not None and
                    "allow-scripts" in i["sandbox"] and "allow-same-origin" in i["sandbox"]]
            if weak:
                self.add("R51", FAIL, "Sandbox inefficace (allow-scripts + allow-same-origin)",
                         "", weak)
        # R58 : JSON-P
        jsonp = [urljoin(base, s["src"]) for s in p.scripts
                 if re.search(r"[?&](callback|jsonp|cb)=", s["src"], re.I)]
        self.add("R58", FAIL if jsonp else PASS, "Usage de JSON-P",
                 f"{len(jsonp)} script(s) de type JSON-P" if jsonp else "Aucun détecté", jsonp)
        # R38 : formulaires POST sans jeton apparent
        body = self.final.text
        posts = [f for f in p.forms if (f.get("method") or "").lower() == "post"]
        if posts:
            has_token = re.search(r"name=[\"']?[^\"'>]*(csrf|xsrf|token|authenticity)", body, re.I)
            self.add("R38", PASS if has_token else WARN, "Jeton anti-CSRF dans les formulaires",
                     "Champ de jeton détecté" if has_token else
                     f"{len(posts)} formulaire(s) POST sans champ de jeton apparent")

    # --- JavaScript --------------------------------------------------------
    def check_js(self):
        base = self.final.url
        sources: List[Tuple[str, str]] = [(f"{base} (inline #{i + 1})", s)
                                          for i, s in enumerate(self.page.inline_scripts) if s.strip()]
        fetched = 0
        for s in self.page.scripts:
            full = urljoin(base, s["src"])
            if urlparse(full).scheme not in ("http", "https"):
                continue
            if not same_site(full, base) and not self.args.scan_third_party:
                continue
            if fetched >= self.args.max_scripts:
                break
            try:
                self.log(f"analyse JS {full[:90]}")
                r = self.http.request(full)
                if r.status == 200:
                    sources.append((full, r.text))
                    fetched += 1
                    ct = (r.get("Content-Type") or "").lower()
                    if "javascript" not in ct and "ecmascript" not in ct:
                        self.add("R6", WARN, "Script servi avec un Content-Type inadapté",
                                 f"{full} : {ct or 'absent'}")
            except (OSError, http.client.HTTPException, ssl.SSLError):
                continue
        hits: Dict[Tuple[str, str], List[str]] = {}
        strict_count = 0
        libs: Dict[str, str] = {}
        for name, code in sources:
            for rid, label, rx in JS_PATTERNS:
                for m in rx.finditer(code):
                    if rid == "R47":
                        strict_count += 1
                        break
                    if rid == "R45" and re.search(r"noopener", m.group(0)):
                        continue
                    if rid == "R45" and m.group(1).count(",") < 1:
                        continue  # pas de 2e paramètre target
                    ln = code.count("\n", 0, m.start()) + 1
                    snippet = code[max(0, m.start() - 20): m.end() + 30].replace("\n", " ")
                    hits.setdefault((rid, label), []).append(f"{name}:{ln} … {snippet.strip()[:110]}")
            for lib, rx, minv in KNOWN_LIBS:
                m = rx.search(code) or rx.search(name)
                if m:
                    libs[lib] = next(g for g in m.groups() if g)
        for s in self.page.scripts:
            for lib, rx, minv in KNOWN_LIBS:
                m = rx.search(s["src"])
                if m and lib not in libs:
                    libs[lib] = next(g for g in m.groups() if g)

        severity = {"R9": FAIL, "R10": FAIL, "R25": FAIL, "R57": FAIL, "R54": FAIL,
                    "R4": WARN, "R45": WARN, "R23": MANUAL, "R24": MANUAL, "R44": INFO,
                    "R55": MANUAL}
        detail = {
            "R4": "Préférer textContent, setAttribute, createElement ou Trusted Types.",
            "R23": "Vérifier qu'aucune donnée sensible n'y est stockée.",
            "R24": "Vérifier qu'aucune donnée sensible n'y est stockée.",
            "R44": "Préférer l'API Fetch.",
            "R55": "Vérifier que chaque écouteur contrôle event.origin avant tout traitement.",
            "R54": "Toujours préciser l'Origin cible de postMessage.",
        }
        for (rid, label), ev in hits.items():
            self.add(rid, severity.get(rid, WARN), f"{label} ({len(ev)} occurrence(s))",
                     detail.get(rid, ""), ev)
        for rid in ("R9", "R10", "R25", "R57", "R54"):
            if not any(k[0] == rid for k in hits):
                self.add(rid, PASS, "Aucune occurrence détectée dans le JavaScript analysé",
                         f"{len(sources)} source(s) analysée(s)")
        if sources:
            self.add("R47", PASS if strict_count else WARN, "Mode strict",
                     f"'use strict' trouvé dans {strict_count}/{len(sources)} source(s) "
                     "(les modules ES et classes sont implicitement stricts)")
        for lib, v in libs.items():
            minv = next(m for l, _, m in KNOWN_LIBS if l == lib)
            old = vtuple(v) < vtuple(minv)
            if lib == "AngularJS":
                self.add("R62", FAIL, f"{lib} {v} détecté", "AngularJS est en fin de vie depuis 2022.")
            else:
                self.add("R62", WARN if old else INFO, f"{lib} {v} détecté",
                         f"Versions antérieures à {minv} présentant des vulnérabilités connues"
                         if old else "Vérifier qu'il s'agit de la dernière version.")
        self.add("R61", INFO, "Scripts externes chargés",
                 f"{len(self.page.scripts)} script(s) externe(s), dont "
                 f"{sum(1 for s in self.page.scripts if not same_site(urljoin(base, s['src']), base))}"
                 " tiers", [urljoin(base, s["src"]) for s in self.page.scripts])

    # --- Divers ------------------------------------------------------------
    def check_misc(self):
        r = self.final
        # Profils de déploiement (R60) : indices d'environnement de dev
        leaks = []
        for h in ("X-Powered-By", "Server", "X-AspNet-Version", "X-Debug-Token", "X-Debug-Token-Link"):
            if r.get(h) and (h != "Server" or re.search(r"\d", r.get(h))):
                leaks.append(f"{h}: {r.get(h)}")
        if re.search(r"sourceMappingURL=", r.text):
            leaks.append("sourceMappingURL présent (cartes sources exposées)")
        if re.search(r"(Traceback \(most recent call last\)|Whoops!|Symfony Profiler|"
                     r"DEBUG\s*=\s*True|Stack trace:)", r.text):
            leaks.append("Trace de débogage dans la page")
        self.add("R60", WARN if leaks else PASS, "Indices d'un profil non adapté à la production",
                 "Masquer les versions et désactiver le mode debug." if leaks else "", leaks)
        # Permissions-Policy (défense en profondeur)
        pp = r.get("Permissions-Policy")
        self.add("R13", PASS if pp else INFO, "Permissions-Policy" + (" définie" if pp else " absente"),
                 pp or "Recommandé en défense en profondeur (camera=(), microphone=(), …)")
        # Contrôle des en-têtes sur des URL supplémentaires (API)
        for extra in self.args.extra_url or []:
            try:
                rr = self.http.request(extra, headers={"Origin": "https://anssi-audit-evil.example"})
            except (OSError, http.client.HTTPException, ssl.SSLError) as e:
                self.add("R40", INFO, f"{extra} injoignable", str(e))
                continue
            ct = rr.get("Content-Type")
            self.add("R6", PASS if ct else FAIL, f"{extra} : Content-Type", ct or "absent")
            if "json" in (ct or "").lower() and "nosniff" not in (rr.get("X-Content-Type-Options") or ""):
                self.add("R34", WARN, f"{extra} : réponse JSON sans X-Content-Type-Options: nosniff")
            acao = rr.get("Access-Control-Allow-Origin")
            if acao == "https://anssi-audit-evil.example":
                self.add("R40", FAIL, f"{extra} : Origin arbitraire acceptée",
                         f"ACAC={rr.get('Access-Control-Allow-Credentials')}")
            elif acao:
                self.add("R40", INFO, f"{extra} : Access-Control-Allow-Origin", acao)
            else:
                self.add("R40", PASS, f"{extra} : Origin arbitraire refusée")

    def add_manual(self):
        host = urlparse(self.url).hostname or ""
        covered = {f.reco for f in self.findings if f.status != MANUAL}
        for rid, txt in MANUAL_CHECKS.items():
            if rid not in covered or rid in ("R3", "R7", "R8", "R62"):
                self.add(rid, MANUAL, "À vérifier manuellement", txt.format(host=host))

    def run(self) -> List[Finding]:
        self.check_transport()
        if self.fetch_page():
            self.check_hsts()
            self.check_content_type()
            self.check_csp()
            self.check_xfo()
            self.check_referrer()
            self.check_coop()
            self.check_cookies()
            self.check_cors()
            self.check_html()
            self.check_js()
            self.check_misc()
        self.add_manual()
        return self.findings


# ---------------------------------------------------------------------------
# Rapports
# ---------------------------------------------------------------------------

COLORS = {PASS: "\033[32m", FAIL: "\033[31m", WARN: "\033[33m", INFO: "\033[36m",
          MANUAL: "\033[35m", NA: "\033[90m"}


def rnum(rid: str) -> int:
    return int(re.sub(r"\D", "", rid) or 0)


def summarize(findings: List[Finding]) -> Dict[str, int]:
    return {s: sum(1 for f in findings if f.status == s) for s in STATUS_ORDER}


def score(findings: List[Finding]) -> int:
    auto = [f for f in findings if f.status in (PASS, WARN, FAIL)]
    if not auto:
        return 0
    pts = sum(1 if f.status == PASS else 0.5 if f.status == WARN else 0 for f in auto)
    return round(100 * pts / len(auto))


def print_report(url: str, findings: List[Finding], color: bool, verbose: bool):
    c = (lambda s: COLORS.get(s, "")) if color else (lambda s: "")
    reset = "\033[0m" if color else ""
    bold = "\033[1m" if color else ""
    print(f"\n{bold}Audit ANSSI-PA-009 v2.0 — {url}{reset}")
    print(f"Date : {dt.datetime.now():%Y-%m-%d %H:%M}\n")
    for rid in sorted({f.reco for f in findings}, key=rnum):
        items = [f for f in findings if f.reco == rid]
        if not verbose and all(f.status in (MANUAL, NA) for f in items):
            continue
        print(f"{bold}{rid} — {RECOS.get(rid, '')}{reset}")
        for f in sorted(items, key=lambda x: STATUS_ORDER.index(x.status)):
            if not verbose and f.status in (MANUAL, NA):
                continue
            print(f"  {c(f.status)}[{f.status:^9}]{reset} {f.title}")
            if f.detail:
                print(f"              {f.detail}")
            if verbose or f.status in (FAIL, WARN):
                for e in f.evidence[:6]:
                    print(f"              · {e}")
    s = summarize(findings)
    print(f"\n{bold}Synthèse{reset} : " + "  ".join(f"{c(k)}{k}: {v}{reset}" for k, v in s.items()))
    print(f"Score automatique : {score(findings)}/100 "
          f"(sur les contrôles automatisés uniquement)")
    if not verbose:
        print(f"{s[MANUAL]} point(s) à vérifier manuellement : relancer avec -v ou consulter "
              "le rapport JSON/HTML.")


def html_report(url: str, findings: List[Finding]) -> str:
    colors = {PASS: "#1a7f37", FAIL: "#cf222e", WARN: "#9a6700", INFO: "#0969da",
              MANUAL: "#8250df", NA: "#6e7781"}
    s = summarize(findings)
    rows = []
    for rid in sorted({f.reco for f in findings}, key=rnum):
        for f in sorted([f for f in findings if f.reco == rid],
                        key=lambda x: STATUS_ORDER.index(x.status)):
            ev = "".join(f"<li><code>{html.escape(e)}</code></li>" for e in f.evidence)
            rows.append(
                f"<tr><td><b>{rid}</b><br><small>{html.escape(RECOS.get(rid, ''))}</small></td>"
                f"<td><span class=b style='background:{colors[f.status]}'>{f.status}</span></td>"
                f"<td>{html.escape(f.title)}<br><small>{html.escape(f.detail)}</small>"
                f"{'<ul>' + ev + '</ul>' if ev else ''}</td></tr>")
    badges = " ".join(f"<span class=b style='background:{colors[k]}'>{k} : {v}</span>"
                      for k, v in s.items())
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit ANSSI – {html.escape(url)}</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:24px;color:#1f2328}}
table{{border-collapse:collapse;width:100%}}td{{border-bottom:1px solid #d0d7de;padding:8px;vertical-align:top}}
.b{{color:#fff;border-radius:4px;padding:2px 8px;font-size:12px;white-space:nowrap}}
code{{font-size:12px;word-break:break-all}}small{{color:#59636e}}ul{{margin:4px 0 0 16px;padding:0}}</style>
</head><body><h1>Audit de sécurité navigateur (ANSSI-PA-009 v2.0)</h1>
<p><b>Cible :</b> {html.escape(url)}<br><b>Date :</b> {dt.datetime.now():%Y-%m-%d %H:%M}<br>
<b>Score automatique :</b> {score(findings)}/100<br>
<b>Référentiel :</b> <a href="{GUIDE_URL}">guide ANSSI</a></p><p>{badges}</p>
<table><tbody>{''.join(rows)}</tbody></table></body></html>"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit de sécurité côté navigateur selon le guide ANSSI-PA-009 v2.0.")
    ap.add_argument("url", help="URL de l'application à auditer (ex. https://exemple.fr)")
    ap.add_argument("--cookie", help="En-tête Cookie à envoyer (audit d'une page authentifiée)")
    ap.add_argument("-H", "--header", action="append", help="En-tête supplémentaire « Nom: valeur »")
    ap.add_argument("--extra-url", action="append",
                    help="URL supplémentaire (ex. point d'API) à contrôler (CORS, Content-Type)")
    ap.add_argument("--scan-third-party", action="store_true",
                    help="Analyser aussi le JavaScript servi par des domaines tiers")
    ap.add_argument("--max-scripts", type=int, default=25, help="Nombre max. de scripts analysés")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="Ne pas vérifier le certificat pour les requêtes HTTP (tests internes)")
    ap.add_argument("--json", metavar="FICHIER", help="Écrire le rapport JSON")
    ap.add_argument("--html", metavar="FICHIER", help="Écrire le rapport HTML")
    ap.add_argument("--fail-on", choices=["fail", "warn", "never"], default="fail",
                    help="Code retour non nul si ÉCHEC (défaut) / ATTENTION / jamais (CI)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Afficher tous les contrôles")
    ap.add_argument("-q", "--quiet", action="store_true", help="Pas de messages de progression")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)

    url = args.url if "://" in args.url else "https://" + args.url
    findings = Auditor(url, args).run()
    print_report(url, findings, sys.stdout.isatty() and not args.no_color, args.verbose)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"target": url, "date": dt.datetime.now().isoformat(timespec="seconds"),
                       "guide": "ANSSI-PA-009 v2.0", "score": score(findings),
                       "summary": summarize(findings),
                       "findings": [dict(asdict(f), reco_title=RECOS.get(f.reco, ""))
                                    for f in findings]},
                      fh, ensure_ascii=False, indent=2)
        print(f"Rapport JSON : {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_report(url, findings))
        print(f"Rapport HTML : {args.html}")

    s = summarize(findings)
    if args.fail_on == "fail" and s[FAIL]:
        return 2
    if args.fail_on == "warn" and (s[FAIL] or s[WARN]):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
