# SOC SecuriGlass — Pile Wazuh de démonstration

> **Statut** : livrable de conception et de configuration. La pile **n'a pas été
> démarrée** dans le cadre de cette livraison (pas de `docker compose up`, pas de
> test d'ingestion réel). Les vérifications effectuées sont listées dans
> [`REPORT.md`](REPORT.md).

## 1. Rôle dans l'architecture Purdue

| Niveau | Composant | Rôle |
| :--- | :--- | :--- |
| 3 (salle de contrôle) | Passerelle edge, Suricata OT | Émet les événements Modbus/TCP 5020 et les journaux de zone |
| 3,5 (DMZ industrielle) | Exportateur d'audit SecuriGlass | Normalise `sec_data.audit_logs` en JSON Lines |
| 4 (SOC) | **Wazuh manager** | Décodage, corrélation, FIM, alertes |
| 4 (SOC) | **Wazuh indexer + dashboard** | Stockage et visualisation (TLS mutuel) |

Le SOC est un **consommateur passif** : aucune action de contrôle n'est renvoyée
vers l'OT (pas d'Active Response), afin de ne jamais perturber un procédé
verrier en cours.

## 2. Prérequis

* Docker Engine ≥ 24 et Docker Compose ≥ 2.20.
* 5 Go de RAM libres (8 Go recommandés), 10 Go de disque.
* `openssl` (génération de la PKI), `htpasswd` **ou** le paquet Python `bcrypt`
  (hash des comptes Wazuh), `python3`.
* Ports locaux : `8443` (dashboard), `9200` (indexeur), `55000` (API manager),
  `1514/tcp` et `1515/tcp` (agents), `514/udp` (syslog OT).

## 3. Démarrage

```bash
cd siem
./scripts/bootstrap.sh        # .env + PKI + internal_users.yml + wazuh.yml
docker compose up -d
docker compose ps
```

* Dashboard : <https://127.0.0.1:8443> (certificat interne auto-signé).
* Identifiants : `admin` + `INDEXER_PASSWORD` de `siem/.env`. **Ne jamais
  commiter `.env`** (déjà dans `.gitignore`).
* Pour tout réinitialiser : `docker compose down -v` puis relancer le bootstrap
  avec `--force` pour la PKI (`./scripts/generate-certs.sh --force`).

### Limites mémoire (documentées et appliquées)

| Service | `mem_limit` | `mem_reservation` | Justification |
| :--- | ---: | ---: | :--- |
| `wazuh.indexer` | 2 Go | 1 Go | Tas JVM `-Xms1g -Xmx1g` + overhead OpenSearch |
| `wazuh.manager` | 1 Go | 512 Mo | Analyse, FIM, filebeat |
| `wazuh.dashboard` | 768 Mo | 384 Mo | Node.js + plugin Wazuh |
| **Total** | **~3,8 Go** | **~1,9 Go** | Prévoir 5 Go libres minimum |

Réduire le tas JVM dans `.env` (`INDEXER_JAVA_OPTS="-Xms512m -Xmx512m"`) sur un
poste à 8 Go.

## 4. Collecte des journaux

Le manager monte `siem/logs/` en **lecture seule** sur `/var/log/securiglass`.
L'exportateur (ou l'agent Wazuh) doit y déposer :

| Fichier | Format | Contenu |
| :--- | :--- | :--- |
| `audit.jsonl` | JSON Lines | Audit applicatif SecuriGlass |
| `backend-api.log` | texte | Journaux FastAPI (repli) |
| `postgresql.log` | texte | Journaux PostgreSQL/pgAudit (`AUDIT:`) |
| `suricata/eve.json` | JSON Lines | EVE JSON Suricata (Modbus, flux) |
| `sealed/*.sha256` | texte | Manifestes scellés quotidiens (FIM) |

### Contrat JSON `audit.jsonl`

Une ligne = un événement, sans secret :

```json
{
  "source": "securiglass.audit",
  "event_time": "2026-10-24T18:00:00.123456+00:00",
  "event_type": "AUTH_LOGIN",
  "actor_username": "operator1",
  "actor_ip": "10.10.20.15",
  "action": "LOGIN",
  "resource": "/api/v1/auth/login",
  "outcome": "FAILURE",
  "details": {"reason": "invalid_password", "attempt_count": 4},
  "prev_log_hash": "…",
  "current_hash": "…"
}
```

Champs enrichis attendus par les règles Sigma (calculés par le normalisateur
`services/soc-siem`, ou déjà présents dans l'audit) :

| Champ | Fenêtre | Rôle |
| :--- | :--- | :--- |
| `details.attempt_count` | compteur backend | échecs consécutifs par compte (remis à zéro après succès) |
| `details.prior_failures` | 15 min | échecs avant un succès (Sigma 003) |
| `details.denied_count` | 10 min | refus RBAC pour le même acteur (Sigma 005) |
| `outside_schedule` | — | `true` si l'ordre OT sort de 05:45–22:15 (Sigma 006) |
| `details.cert_status` | — | `REVOKED` pour un certificat edge révoqué (Sigma 008) |
| `details.record_count` | — | nombre d'enregistrements clients renvoyés (Sigma 009) |

> Sans ces champs, les règles concernées ne se déclenchent pas : le contrat de
> données fait partie intégrante de la détection.

## 5. Contenu Wazuh

### `wazuh/ossec.conf`

* FIM temps réel : `/etc`, `/etc/ssh`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`,
  `etc/rules`, `etc/decoders`, `logs/sealed`.
* `nodiff` sur `/etc/shadow`, clés SSH, `client.keys` : aucun secret dans les
  différences FIM.
* Collecte `localfile` (JSON + syslog) pour les quatre sources.
* `remote` syslog restreint à `10.10.20.0/24` et `10.10.30.0/24`.
* Indexation TLS vers `wazuh.indexer` (CA interne, vérification complète).
* SCA, syscollector et flux de vulnérabilités désactivés (pile légère, réseau
  OT isolé).
* **Aucune Active Response** : le confinement est manuel (voir registre
  d'incidents).

### Décodeurs (`wazuh/decoders/`)

| Décodeur | Source | Champs |
| :--- | :--- | :--- |
| `securiglass-audit-json` | `audit.jsonl` | JSON aplati (`details.reason`, …) |
| `securiglass-audit-text` | logger Python | `event_type`, `actor_username`, `outcome`, `audit_hash` |
| `pgaudit` / `pgaudit-postgres` | PostgreSQL | `pgaudit_type`, `pgaudit_class`, `pgaudit_command`, `pgaudit_object_name` |
| `suricata-eve` | EVE JSON | champs JSON (`src_ip`, `dest_port`, `modbus.*`) |
| `ot-modbus-text` | passerelle OT | `src_ip`, `dst_ip`, `dest_port`, `modbus_function` |

### Règles locales (IDs ≥ 100000)

| ID | Niveau | Détection |
| ---: | ---: | :--- |
| 100100 | 0 | base audit applicatif (`source=securiglass.audit`) |
| 100101–100105 | 5–8 | échec/succès login, logout, refus RBAC, refus habilitation |
| 100106 | 12 | échec de vérification de la chaîne SHA-256 |
| 100107–100108 | 1–3 | création / consultation client |
| 100109 | 0 | base télémétrie |
| 100110 | 10 | force brute : 8 échecs/IP/120 s |
| 100111 | 12 | succès après force brute (même IP, 5 min) |
| 100112 | 10 | verrouillage de compte |
| 100113–100114 | 9 | refus RBAC/habilitation répétés |
| 100115–100116 | 10 | modification ABAC (applicatif / pgAudit) |
| 100117–100119 | 8–15 | DDL, rôles, UPDATE/DELETE sur `audit_logs` |
| 100120 | 8 | extraction ≥ 1000 clients |
| 100121–100122 | 8–10 | Modbus 5020 depuis un réseau non-OT, écriture |
| 100123 / 100128 | 9 | écriture procédé hors 05:45–22:15 (heure serveur / drapeau) |
| 100124 | 12 | certificat edge révoqué |
| 100125 | 9 | écriture registre critique 0–9 |
| 100126–100127 | 8–12 | FIM fichier système / manifeste scellé |
| 100129 | 9 | 10 consultations clients en 60 s |

## 6. Sigma et YARA

* `sigma/` : 10 règles valides pySigma 1.5.1, IDs UUID uniques, champs
  obligatoires contrôlés par `tests/test_rules.py`.
* `yara/` : 3 règles compilées avec yara-python 4.5.4 (webshell, payload
  Modbus, binaire OT).
* Conversion Sigma (exemple) :

```bash
siem/.venv/bin/python - <<'PY'
from pathlib import Path
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
c = SigmaCollection.from_yaml(Path("siem/sigma/007_modbus_from_non_ot_network.yml").read_text())
print(SplunkBackend().convert(c)[0])
PY
```

## 7. Vérifications reproductibles

```bash
# Depuis la racine du dépôt
siem/.venv/bin/python -m py_compile redteam/*.py
siem/.venv/bin/python -m pytest redteam/tests siem/tests -q
docker compose --env-file siem/.env.example -f siem/docker-compose.yml config --quiet
```

Les résultats réels sont dans [`REPORT.md`](REPORT.md).

## 8. Ce qui n'est pas couvert

* Démarrage réel de la pile, ingestion d'un agent, test de `wazuh-logtest`.
* Déploiement d'un agent Wazuh sur la gateway edge et sur le backend.
* Capteur Suricata OT (configuration réseau, règles de détection Modbus).
* Exportateur PostgreSQL → `audit.jsonl` (le contrat est défini, le service
  n'est pas livré ici).
* Rotation automatique des certificats et des secrets.
* Haute disponibilité, sauvegarde/restauration de l'indexeur.

Voir `REPORT.md` §« Non vérifié » pour la liste exhaustive et les prochaines
étapes.
