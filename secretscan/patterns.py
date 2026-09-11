"""Catalogue des motifs recherchés.

Chaque entrée : (nom, sévérité, expression compilée, groupe qui contient le secret).
Le groupe sert à masquer précisément la valeur dans l'extrait affiché ;
0 signifie « toute la correspondance ».

Les motifs sont volontairement conservateurs : mieux vaut manquer une forme
exotique que noyer l'analyste sous les faux positifs. Les valeurs déjà
masquées (« *** », « [REDACTED] »…) sont écartées par le scanner.
"""

import re

PATTERNS = [
    (
        "Clé privée",
        "CRITIQUE",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        0,
    ),
    (
        "Identifiants dans une URL",
        "ÉLEVÉE",
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:([^@\s/]+)@", re.I),
        1,
    ),
    (
        "Mot de passe en clair",
        "ÉLEVÉE",
        re.compile(
            r"\b(?:pass(?:word|wd|phrase)?|pwd|mot_de_passe|motdepasse)\s*[=:]\s*[\"']?([^\s\"',;]{4,})",
            re.I,
        ),
        1,
    ),
    (
        "Authentification HTTP Basic",
        "ÉLEVÉE",
        re.compile(r"authorization\s*[:=]\s*[\"']?basic\s+([a-z0-9+/=]{8,})", re.I),
        1,
    ),
    (
        "Jeton Bearer",
        "ÉLEVÉE",
        re.compile(r"authorization\s*[:=]\s*[\"']?bearer\s+([a-z0-9\-._~+/]{16,}=*)", re.I),
        1,
    ),
    (
        "Clé d'accès AWS",
        "ÉLEVÉE",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        1,
    ),
    (
        "Jeton GitHub",
        "ÉLEVÉE",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"),
        1,
    ),
    (
        "Jeton Slack",
        "ÉLEVÉE",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        1,
    ),
    (
        "JWT",
        "MOYENNE",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        1,
    ),
    (
        "Clé d'API ou secret applicatif",
        "MOYENNE",
        re.compile(
            r"\b(?:api[_-]?key|apikey|access[_-]?token|client[_-]?secret|secret[_-]?key|auth[_-]?token)"
            r"\s*[=:]\s*[\"']?([A-Za-z0-9\-_.]{16,})",
            re.I,
        ),
        1,
    ),
]

SEVERITY_ORDER = {"CRITIQUE": 0, "ÉLEVÉE": 1, "MOYENNE": 2, "FAIBLE": 3}
