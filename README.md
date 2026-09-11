# log-secret-scanner

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white) ![Bibliothèque standard](https://img.shields.io/badge/d%C3%A9pendances-aucune-2E7D32) ![Tests](https://img.shields.io/badge/tests-unittest-455A64) ![Licence MIT](https://img.shields.io/badge/licence-MIT-546E7A)

**FR** — Détecte des secrets en clair — mots de passe, jetons, clés — dans des journaux et fichiers de configuration, et les affiche **masqués**. Outil de sécurité opérationnelle, Python 3, bibliothèque standard uniquement.

**EN** — Detects clear-text secrets — passwords, tokens, keys — in log and configuration files and reports them **redacted**. An operational-security tool, Python 3, standard library only.

---

## Français

### Objectif

Automatiser la recherche de secrets journalisés en clair dans une arborescence de journaux (archives tournées comprises), pour pouvoir **signaler et faire corriger** la journalisation à la source, sans jamais afficher le secret lui-même.

### Contexte cybersécurité

En exploitation, un service qui journalise une chaîne de connexion, un en-tête `Authorization` ou un mot de passe d'échec d'authentification expose ces secrets à toute personne ayant accès aux journaux, et à la plateforme de collecte centralisée (rsyslog, Elasticsearch…) où ils sont ensuite indexés. Cet outil est né d'un cas réel rencontré en alternance : des secrets applicatifs retrouvés en clair dans des journaux, identifiés puis remontés à l'éditeur.

### Fonctionnalités

- 10 motifs : clé privée, identifiants dans une URL, mot de passe `clé=valeur`, HTTP Basic, Bearer, clé d'accès AWS, jetons GitHub et Slack, JWT, clé d'API ou secret applicatif.
- Sévérité par motif (CRITIQUE, ÉLEVÉE, MOYENNE) et **code de sortie** : `2` si un constat CRITIQUE ou ÉLEVÉE, `1` si uniquement MOYENNE, `0` sinon.
- Les valeurs déjà masquées par l'application (`********`, `[REDACTED]`, `${VAR}`…) sont ignorées.
- Quand plusieurs motifs se recouvrent, un seul constat est conservé.
- Lecture en flux, fichier par fichier : fonctionne sur des journaux de plusieurs Go.
- Archives `.gz` lues directement ; journaux tournés (`app.log.1`, `app.log.2.gz`) reconnus.
- Fichiers binaires ignorés ; extensions de journaux et de configuration par défaut, `--all` pour tout scanner.
- `--ignore REGEX` pour écarter des lignes connues ; sortie texte groupée par fichier, ou `--json`.

### Technologies et outils

- Python 3.8+ : `re`, `gzip`, `os`, `argparse`, `json`
- Aucune dépendance externe, aucun accès réseau
- Tests : `unittest`

```
scan_secrets.py       point d'entrée CLI (affichage, code de sortie)
secretscan/
  patterns.py         catalogue des motifs et sévérités
  scanner.py          parcours, lecture en flux (.gz inclus), masquage, dédoublonnage
tests/
  test_scanner.py     tests unitaires
samples/
  app.log             journal d'exemple avec secrets fictifs
```

### Compatibilité

Fonctionne sous Windows, Linux et macOS : Python 3.7 ou plus, bibliothèque standard uniquement, aucun paquet à installer. Seul le nom de la commande Python change selon le système.

| Système | Vérifier Python | Lancer l'outil | Lancer les tests |
|---|---|---|---|
| Windows (PowerShell ou Invite de commandes) | `py --version` ou `python --version` | `py scan_secrets.py samples/` | `py -m unittest discover -s tests -v` |
| Linux (Debian, Ubuntu…) | `python3 --version` | `python3 scan_secrets.py samples/` | `python3 -m unittest discover -s tests -v` |
| macOS | `python3 --version` | `python3 scan_secrets.py samples/` | `python3 -m unittest discover -s tests -v` |

Les exemples ci-dessous utilisent `python` : remplacer par `py` ou `python3` si nécessaire. Sous Windows, préférer PowerShell ou Windows Terminal pour l'affichage correct des accents et des couleurs.

### Installation

```bash
git clone https://github.com/Lenu-san/log-secret-scanner.git
cd log-secret-scanner
python scan_secrets.py samples/
```

### Utilisation

```bash
python scan_secrets.py samples/
python scan_secrets.py /var/log/app --min-severite ÉLEVÉE
python scan_secrets.py exports/ --all --include-hidden
python scan_secrets.py app.log --ignore "test fixture|exemple"
python scan_secrets.py /var/log/app --json > constats.json
python -m unittest discover -s tests -v
```

### Résultats

Sur `samples/app.log` :

```
samples/app.log
  ÉLEVÉE   ligne 2      Identifiants dans une URL
           2026-09-08 08:00:01 INFO  db   connexion à postgres://app:[MASQUÉ]@db01.intra.example.org:5432/app
  ÉLEVÉE   ligne 5      Authentification HTTP Basic
           2026-09-08 08:01:12 DEBUG http en-têtes reçus: Authorization: Basic [MASQUÉ] User-Agent: curl/8.4
  ÉLEVÉE   ligne 7      Clé d'accès AWS
           2026-09-08 08:02:40 INFO  sync export vers S3 avec aws_access_key_id=[MASQUÉ]
  ...

Bilan — ÉLEVÉE: 5  MOYENNE: 1  (6 constat(s))
```

La ligne 6 (`password=********`) et la ligne 9 (`[REDACTED]`) ne remontent pas : elles sont déjà masquées. 11 tests unitaires passants.

Le rapport reste sensible (il indique **où** chercher) : à traiter comme un constat d'audit.

### Limites

- **Détection par motifs** : un secret sans mot-clé reconnaissable n'est pas détecté ; des faux positifs restent possibles sur des valeurs qui ressemblent à un jeton.
- Mots-clés en anglais et en français (`password`, `pwd`, `mot_de_passe`), pas dans d'autres langues.
- Pas de détection par entropie : choix volontaire pour limiter le bruit.
- Une ligne est analysée isolément : une clé privée est repérée par son en-tête, pas reconstituée.
- Archives autres que `.gz` (zip, xz, bz2) non lues.

### Améliorations possibles

- Fichier de motifs personnalisés (`--patterns motifs.json`) pour les formats internes d'une organisation.
- Prise en charge de `.bz2` et `.xz`.
- Option d'entropie activable pour les chaînes longues à fort désordre.
- Sortie SARIF pour intégration dans une CI.

---

## English

### Objective

Automate the search for secrets logged in clear text across a log tree (rotated archives included), so that the logging can be **reported and fixed at the source**, without ever displaying the secret itself.

### Cybersecurity context

In operations, a service that logs a connection string, an `Authorization` header or a failed-login password exposes those secrets to anyone with access to the logs, and to the central collection platform (rsyslog, Elasticsearch…) where they are then indexed. This tool grew out of a real case met during my apprenticeship: application secrets found in clear text in logs, identified and escalated to the vendor.

### Features

- 10 patterns: private key, credentials in a URL, `key=value` password, HTTP Basic, Bearer, AWS access key, GitHub and Slack tokens, JWT, API key or application secret.
- Per-pattern severity (CRITIQUE, ÉLEVÉE, MOYENNE) and **exit code**: `2` for a CRITICAL or HIGH finding, `1` for MEDIUM only, `0` otherwise.
- Values already masked by the application (`********`, `[REDACTED]`, `${VAR}`…) are ignored.
- Overlapping patterns yield a single finding.
- Streaming read, file by file: works on multi-GB logs.
- `.gz` archives read directly; rotated logs (`app.log.1`, `app.log.2.gz`) recognised.
- Binary files skipped; default log and configuration extensions, `--all` to scan everything.
- `--ignore REGEX` to drop known lines; text output grouped by file, or `--json`.

### Technologies and tools

- Python 3.8+: `re`, `gzip`, `os`, `argparse`, `json`
- No external dependency, no network access
- Tests: `unittest`

```
scan_secrets.py       CLI entry point (output, exit code)
secretscan/
  patterns.py         pattern catalogue and severities
  scanner.py          tree walk, streaming read (.gz included), redaction, deduplication
tests/
  test_scanner.py     unit tests
samples/
  app.log             sample log with fictional secrets
```

### Compatibility

Runs on Windows, Linux and macOS: Python 3.7 or later, standard library only, nothing to install. Only the name of the Python command differs between systems.

| System | Check Python | Run the tool | Run the tests |
|---|---|---|---|
| Windows (PowerShell or Command Prompt) | `py --version` or `python --version` | `py scan_secrets.py samples/` | `py -m unittest discover -s tests -v` |
| Linux (Debian, Ubuntu…) | `python3 --version` | `python3 scan_secrets.py samples/` | `python3 -m unittest discover -s tests -v` |
| macOS | `python3 --version` | `python3 scan_secrets.py samples/` | `python3 -m unittest discover -s tests -v` |

The examples below use `python`: replace with `py` or `python3` where needed. On Windows, prefer PowerShell or Windows Terminal so that accented characters and colours display correctly.

### Installation

```bash
git clone https://github.com/Lenu-san/log-secret-scanner.git
cd log-secret-scanner
python scan_secrets.py samples/
```

### Usage

```bash
python scan_secrets.py samples/
python scan_secrets.py /var/log/app --min-severite ÉLEVÉE
python scan_secrets.py exports/ --all --include-hidden
python scan_secrets.py app.log --ignore "test fixture|example"
python scan_secrets.py /var/log/app --json > findings.json
python -m unittest discover -s tests -v
```

Output messages are in French.

### Results

On `samples/app.log`: 6 findings (5 high, 1 medium), every excerpt redacted as `[MASQUÉ]` (see the French section for the full output). Line 6 (`password=********`) and line 9 (`[REDACTED]`) are not reported: they are already masked. 11 passing unit tests.

The report remains sensitive (it says **where** to look): treat it as an audit finding.

### Limitations

- **Pattern-based detection**: a secret without a recognisable keyword is not detected; false positives remain possible on token-like values.
- Keywords in English and French (`password`, `pwd`, `mot_de_passe`), not other languages.
- No entropy-based detection: a deliberate choice to limit noise.
- Each line is analysed on its own: a private key is spotted by its header, not reconstructed.
- Archives other than `.gz` (zip, xz, bz2) are not read.

### Possible improvements

- Custom pattern file (`--patterns patterns.json`) for an organisation's internal formats.
- `.bz2` and `.xz` support.
- Optional entropy check for long high-entropy strings.
- SARIF output for CI integration.

---

## Auteur / Author

**Lénusan Gunarajah** — ingénieur cybersécurité junior : audit de sécurité, sécurité des infrastructures et services managés. / Junior cybersecurity engineer: security auditing, infrastructure security and managed services.

- Portfolio : https://lenu-san.github.io
- GitHub : https://github.com/Lenu-san
- LinkedIn : https://www.linkedin.com/in/l%C3%A9nusan-g-0470b6336

## Licence / License

MIT
