# Service SOC/SIEM — normalisation de l'audit SecuriGlass

Ce répertoire contient le **contrat de normalisation** entre le backend
FastAPI/PostgreSQL et la pile Wazuh (`siem/`). Il ne contient pas de serveur :
l'exportateur PostgreSQL reste un composant d'intégration à déployer sur l'hôte
applicatif.

## 1. Pipeline

```
sec_data.audit_logs (PostgreSQL 16, append-only)
        │  lecture incrémentale (event_time > dernier export)
        ▼
services/soc-siem/normalizer.py
  • source = securiglass.audit
  • srcip = actor_ip
  • details.prior_failures   (fenêtre 15 min)
  • details.denied_count     (fenêtre 10 min)
  • conservation prev_log_hash / current_hash
        │  JSON Lines, une ligne par événement
        ▼
siem/logs/audit.jsonl  ──(volume read-only)──▶  Wazuh manager
        │                                          ├─ décodeur JSON
        │                                          ├─ règles 1001xx
        │                                          └─ Sigma (via backend)
        ▼
Wazuh indexer / dashboard (TLS)
```

## 2. Utilisation du normalisateur

```python
import sys
sys.path.insert(0, "services/soc-siem")   # le repertoire contient un tiret
from normalizer import AuditNormalizer, to_jsonl

normalizer = AuditNormalizer()
for row in rows_from_postgres:          # dict-like asyncpg.Record accepté
    event = normalizer.normalize(row)
    output.write(to_jsonl(event) + "\n")
```

`asyncpg.Record` est un mapping : `dict(row)` fonctionne. Les colonnes attendues
sont celles de `sec_data.audit_logs` :
`event_time, event_type, actor_username, actor_ip, action, resource, outcome,
details, prev_log_hash, current_hash`.

## 3. Garanties

* **Aucune donnée inventée** : les champs absents restent absents ; le
  normalisateur n'ajoute que `source`, `srcip`, `prior_failures` et
  `denied_count`.
* **Aucune mutation** de la ligne source ni du dictionnaire `details`.
* **Horodatage UTC** normalisé (les naive datetimes sont considérées UTC).
* **Fenêtres glissantes** : 15 min pour les échecs, 10 min pour les refus RBAC.
* **Pas de secret** : le flux ne contient ni mot de passe, ni JWT, ni clé.

## 4. Tests

```bash
siem/.venv/bin/python -m pytest siem/tests/test_normalizer.py -q
```

Voir `siem/tests/test_normalizer.py` pour les cas : force brute, succès après
échecs, remise à zéro, refus RBAC répétés, purge de fenêtre.

## 5. Déploiement de l'exportateur (non livré)

L'exportateur doit :

1. se connecter avec un compte PostgreSQL en **lecture seule** sur
   `sec_data.audit_logs` (rôle `role_security_auditor`) ;
2. mémoriser le dernier `event_time` / `id` exporté (fichier d'état ou table
   dédiée) pour éviter les doublons ;
3. écrire de façon atomique (`audit.jsonl.tmp` puis `rename`) ;
4. tourner le fichier quotidiennement et déposer un manifeste
   `audit-AAAAMMJJ.jsonl.sha256` dans `siem/logs/sealed/` (surveillé par FIM,
   règle Wazuh 100127) ;
5. ne jamais exposer le flux sur Internet ; le volume `siem/logs/` est monté
   en lecture seule dans le manager.

Le service n'est pas implémenté dans ce PoC : il dépend de la configuration de
l'Étape 2 et du choix de déploiement (cron, sidecar, agent Wazuh).
