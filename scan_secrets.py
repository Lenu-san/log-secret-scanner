#!/usr/bin/env python3
"""log-secret-scanner — point d'entrée CLI.

Recherche des secrets en clair (mots de passe, jetons, clés) dans des journaux
et fichiers de configuration, et les affiche masqués.

Exemples :
  python scan_secrets.py samples/
  python scan_secrets.py /var/log/app --min-severite ÉLEVÉE
  python scan_secrets.py exports/*.log.gz --json > constats.json
"""

import argparse
import json
import re
import sys
from collections import Counter

from secretscan import SEVERITY_ORDER, exit_code, scan

# Sous Windows, la console utilise souvent une page de code non-UTF-8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

COLORS = {"CRITIQUE": "\033[35m", "ÉLEVÉE": "\033[31m", "MOYENNE": "\033[33m", "FAIBLE": "\033[36m"}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def color(text, code):
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="scan_secrets",
        description="Détecte des secrets en clair dans des journaux et fichiers texte.",
    )
    parser.add_argument("paths", nargs="+", help="fichiers ou répertoires à analyser")
    parser.add_argument(
        "--min-severite",
        default="FAIBLE",
        choices=list(SEVERITY_ORDER),
        help="n'afficher que les constats d'au moins cette sévérité (le code de sortie tient compte de tout)",
    )
    parser.add_argument("--all", action="store_true", help="scanner tous les fichiers, pas seulement les extensions de journaux")
    parser.add_argument("--include-hidden", action="store_true", help="inclure les fichiers et dossiers cachés")
    parser.add_argument("--ignore", metavar="REGEX", help="ignorer les lignes correspondant à cette expression")
    parser.add_argument("--json", action="store_true", help="sortie JSON (une liste de constats)")
    parser.add_argument("--quiet", action="store_true", help="n'afficher que le bilan")
    args = parser.parse_args(argv)

    ignore = None
    if args.ignore:
        try:
            ignore = re.compile(args.ignore)
        except re.error as err:
            parser.error(f"--ignore : expression invalide ({err})")

    findings = scan(
        args.paths,
        all_files=args.all,
        include_hidden=args.include_hidden,
        ignore=ignore,
    )
    code = exit_code(findings)

    threshold = SEVERITY_ORDER[args.min_severite]
    shown = [f for f in findings if SEVERITY_ORDER[f["severity"]] <= threshold]

    if args.json:
        json.dump(shown, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return code

    if not args.quiet:
        current_file = None
        for finding in shown:
            if finding["file"] != current_file:
                current_file = finding["file"]
                print(color(f"\n{current_file}", BOLD))
            sev = finding["severity"]
            print(
                f"  {color(sev.ljust(8), COLORS[sev])} ligne {finding['line']:<6} {finding['pattern']}"
            )
            print(f"           {color(finding['excerpt'], DIM)}")

    counts = Counter(f["severity"] for f in findings)
    summary = "  ".join(f"{sev}: {counts.get(sev, 0)}" for sev in SEVERITY_ORDER if counts.get(sev))
    if findings:
        print(f"\nBilan — {summary}  ({len(findings)} constat(s))")
    else:
        print("\nAucun secret détecté.")
    return code


if __name__ == "__main__":
    sys.exit(main())
