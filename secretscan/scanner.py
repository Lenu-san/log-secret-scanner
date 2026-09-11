"""Parcours des fichiers, détection ligne par ligne, masquage des extraits.

Les fichiers sont lus en flux (jamais chargés entièrement en mémoire), ce qui
permet de passer sur des journaux de plusieurs Go. Les archives .gz produites
par logrotate sont lues directement.
"""

import gzip
import io
import os
import re

from .patterns import PATTERNS, SEVERITY_ORDER

# Valeurs qui indiquent un secret déjà masqué par l'application : on les ignore.
MASKED = re.compile(
    r"^(?:\*+|x{3,}|#{3,}|<[^>]*>|\[[^\]]*\]|\{[^}]*\}|\$\{[^}]*\}|\$\w+"
    r"|redacted|hidden|masked|filtered|omitted|null|none|undefined|empty"
    r"|changeme|password|secret|example|xxx+)$",
    re.I,
)

# Extensions parcourues par défaut lors d'un scan de répertoire.
DEFAULT_EXTENSIONS = {
    ".log", ".txt", ".out", ".err", ".json", ".gz", ".conf", ".cfg", ".ini",
    ".env", ".yml", ".yaml", ".xml", ".csv", ".properties",
}

MASK = "[MASQUÉ]"
EXCERPT_WIDTH = 160


def _is_masked(value):
    return bool(MASKED.match(value.strip()))


def _excerpt(line, start, end):
    """Ligne avec le secret remplacé, recadrée autour de la correspondance."""
    redacted = line[:start] + MASK + line[end:]
    pivot = start
    if len(redacted) <= EXCERPT_WIDTH:
        return redacted.strip()
    left = max(0, pivot - EXCERPT_WIDTH // 3)
    right = min(len(redacted), left + EXCERPT_WIDTH)
    prefix = "…" if left > 0 else ""
    suffix = "…" if right < len(redacted) else ""
    return prefix + redacted[left:right].strip() + suffix


def scan_line(line):
    """Renvoie les constats d'une ligne : liste de dicts (pattern, severity, excerpt).

    Quand plusieurs motifs se recouvrent (mot de passe dans une URL, par
    exemple), seul le plus sévère est conservé.
    """
    hits = []
    for name, severity, regex, group in PATTERNS:
        for match in regex.finditer(line):
            value = match.group(group)
            if group and _is_masked(value):
                continue
            hits.append(
                {
                    "pattern": name,
                    "severity": severity,
                    "start": match.start(group),
                    "end": match.end(group),
                }
            )

    hits.sort(key=lambda h: (SEVERITY_ORDER[h["severity"]], h["start"]))
    kept = []
    for hit in hits:
        overlaps = any(hit["start"] < k["end"] and k["start"] < hit["end"] for k in kept)
        if not overlaps:
            kept.append(hit)

    return [
        {
            "pattern": h["pattern"],
            "severity": h["severity"],
            "excerpt": _excerpt(line, h["start"], h["end"]),
        }
        for h in sorted(kept, key=lambda h: h["start"])
    ]


def _open_text(path):
    if path.lower().endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace", newline="")


def _looks_binary(path):
    if path.lower().endswith(".gz"):
        return False
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(8192)
    except OSError:
        return True
    return b"\x00" in chunk


def scan_file(path, ignore=None):
    """Scanne un fichier ; renvoie une liste de constats avec fichier et numéro de ligne."""
    findings = []
    if _looks_binary(path):
        return findings
    try:
        with _open_text(path) as handle:
            for lineno, line in enumerate(handle, start=1):
                line = line.rstrip("\r\n")
                if ignore and ignore.search(line):
                    continue
                for hit in scan_line(line):
                    hit["file"] = path
                    hit["line"] = lineno
                    findings.append(hit)
    except (OSError, EOFError, gzip.BadGzipFile):
        # Fichier illisible ou archive corrompue : on passe au suivant.
        return findings
    return findings


def iter_files(paths, all_files=False, include_hidden=False):
    """Énumère les fichiers à scanner à partir de fichiers ou de répertoires."""
    for root_path in paths:
        if os.path.isfile(root_path):
            yield root_path
            continue
        for dirpath, dirnames, filenames in os.walk(root_path):
            if not include_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for name in sorted(filenames):
                if not include_hidden and name.startswith("."):
                    continue
                ext = os.path.splitext(name)[1].lower()
                # journaux tournés : app.log.1, app.log.2.gz
                stem_ext = os.path.splitext(os.path.splitext(name)[0])[1].lower()
                if not all_files and ext not in DEFAULT_EXTENSIONS and stem_ext not in DEFAULT_EXTENSIONS:
                    continue
                yield os.path.join(dirpath, name)


def scan(paths, all_files=False, include_hidden=False, ignore=None):
    findings = []
    for path in iter_files(paths, all_files=all_files, include_hidden=include_hidden):
        findings.extend(scan_file(path, ignore=ignore))
    return findings


def exit_code(findings):
    """2 si un constat CRITIQUE ou ÉLEVÉE, 1 si uniquement MOYENNE/FAIBLE, 0 sinon."""
    if not findings:
        return 0
    worst = min(SEVERITY_ORDER[f["severity"]] for f in findings)
    return 2 if worst <= SEVERITY_ORDER["ÉLEVÉE"] else 1
