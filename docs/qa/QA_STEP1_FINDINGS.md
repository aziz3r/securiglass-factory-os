# 🔍 Rapport QA & DevSecOps — Étape 1 (Fondations Data & IAM)

**Périmètre :** `services/backend-api/app/**`, schémas PostgreSQL et infrastructure Docker.
**Date :** 2026-10-24 — **Verdict : `[STATUT: VALIDÉ]`** sous réserve des points ouverts listés en §6.

---

## 1. Résumé exécutif

| Porte qualité | Commande | Résultat mesuré | Seuil |
| :--- | :--- | :--- | :--- |
| Tests automatisés | `pytest tests/` | **228 passed**, 0 failed, 0 skipped | — |
| Couverture de code | `pytest --cov=app` | **94 %** (811 statements, 50 non couverts) | ≥ 85 % |
| Typage statique | `mypy --strict app` | **0 erreur** (19 fichiers) | 0 |
| Formatage | `black --check app tests` | **39 fichiers conformes** | 100 % |
| Analyse de sécurité (SAST) | `bandit -q -r app -ll` | **0 issue** (medium/high) | 0 |
| Migrations | `alembic upgrade head` | **0001 → 0003** appliquées | — |
| Audit PostgreSQL | `pgAudit` | **actif** — `pgaudit 16.1`, 1 443 lignes `AUDIT:` | obligatoire |
| Immuabilité audit | trigger + chaîne SHA-256 | **altération détectée** (contenu, lien, suppression, réordonnancement) | obligatoire |

Ces chiffres sont reproductibles : voir §7 (procédure).

---

## 2. Environnement de validation

* macOS 27.0 (arm64) + Docker 29.8.1 ; conteneur `securiglass-postgres` (PostgreSQL **16.15**, Debian, non-root).
* Python 3.12.15 (venv `services/backend-api/.venv`).
* Base réelle : `sec_data` (8 tables), `it_data` (4), `ot_data` (10), 6 rôles PostgreSQL, 7 politiques ABAC.
* Les tests d'intégration **écrivent puis annulent** (`ROLLBACK`) leurs données ; seuls les événements d'audit des tests d'API sont persistés (comportement voulu d'une piste d'audit).

---

## 3. Couverture par module

| Module | Couverture |
| :--- | ---: |
| `app/core/config.py` | 100 % |
| `app/core/security.py` | 95 % |
| `app/core/db.py` | 89 % |
| `app/api/auth.py` | 100 % |
| `app/api/customers.py` | 92 % |
| `app/api/deps.py` | 85 % |
| `app/api/audit.py` | 76 % |
| `app/main.py` | 87 % |
| `app/models/schemas.py` | 99 % |
| `app/services/abac_engine.py` | 96 % |
| `app/services/audit_service.py` | 90 % |
| `app/services/tde_service.py` | 100 % |
| **Total** | **94 %** |

---

## 4. Défauts trouvés et corrigés

### D8 — `GET /api/v1/audit/logs` renvoyait 500 (bloquant)
* **Symptôme :** `pydantic_core.ValidationError: details — Input should be a valid dictionary, input_type=str`.
* **Cause :** `asyncpg` désérialise `jsonb` en `str` ; le modèle `AuditLogOut.details` exige `dict | None`.
  Toute ligne d'audit contenant des `details` (donc **tous** les événements d'authentification) faisait échouer l'endpoint.
* **Correctif :** normalisation `_parse_details()` dans `app/api/audit.py` (dict, JSON valide, sinon `None`).
* **Test de non-régression :** `tests/integration/test_api_iam.py::test_audit_logs_can_be_filtered_by_event_type`.

### D9 — Compte `admin` seedé inutilisable (bloquant)
* **Symptôme :** `/api/v1/auth/me` en 500 : `value is not a valid email address: The part after the
  @-sign is a special-use or reserved name`.
* **Cause :** `MeResponse.email: EmailStr` ; `email-validator` refuse les domaines internes `.local`
  (RFC 6762) utilisés par le seed (`admin@securiglass.local`).
* **Correctif :** type `InternalEmail` (validation syntaxique stricte, TLD interne autorisé) pour les
  identités internes ; `EmailStr` conservé pour les données clients (RGPD).
* **Test de non-régression :** `test_me_returns_roles_and_clearance`, `test_login_returns_bearer_token`.

### D10 — Suppression de compte impossible (bloquant, RGPD art. 17)
* **Symptôme :** `VIOLATION CRITIQUE DE SÉCURITÉ : Le journal d audit ... est strictement immuable`
  lors d'un `DELETE FROM sec_data.users`.
* **Cause :** `audit_logs.actor_id REFERENCES users(id) ON DELETE SET NULL` → la suppression d'un
  utilisateur déclenche un `UPDATE` des lignes d'audit, refusé par `trg_audit_logs_immutable`.
* **Correctif :** migration `0003_audit_actor_no_fk` + alignement du DDL `04` : l'audit conserve
  `actor_id` en **instantané** (UUID), sans contrainte référentielle. Même logique pour
  `client_cert_fingerprint` (déjà sans FK).
* **Test de non-régression :** suppression d'utilisateur dans `test_bruteforce_lockout_after_max_failures`
  et `_drop_accounts()` du fixture.

### D1 — Politiques ABAC inversées (corrigé en amont)
* La matrice décrivait des `DENY` dont la condition exprimait le cas **autorisé** : le moteur
  (`condition vraie ⇒ effet appliqué`) refusait le cas nominal et **autorisait** un opérateur hors
  sous-réseau / hors horaires, ainsi qu'un certificat edge révoqué.
* **Correctif appliqué (migration 0002, 7 politiques) :**
  1. `ALLOW_TELEMETRY_READ` — tout compte actif ;
  2. `ALLOW_OT_CONTROL_CONTEXTUAL` — ALLOW **portant** CIDR + horaire + absence de verrou + compte actif ;
  3. `DENY_OT_CONTROL_DURING_MAINTENANCE` — DENY dur ;
  4. `ALLOW_EDGE_TELEMETRY_INSERT` — CIDR gateway + issuer + SAN + hors liste de révocation ;
  5. `DENY_REVOKED_CLIENT_CERT` — DENY dur sur la liste de révocation ;
  6. `ALLOW_RECIPE_APPROVAL_FOUR_EYES` — clearance ≥ 3 **et** créateur différent ;
  7. `DENY_SELF_RECIPE_APPROVAL` — DENY dur sur l'auto-approbation.
* **Tests :** `tests/unit/test_abac_engine.py` (36 cas) + `tests/integration/test_abac_seed.py`
  (le pack **persisté** est rejoué à travers le moteur).

### D3 — pgAudit impossible sur Alpine (corrigé)
* `postgres:16-alpine` + `apk add postgresql16-contrib` ne fournit pas `pgaudit.so` →
  `FATAL: could not access file "pgaudit"`, boucle de redémarrage, **aucun schéma initialisé**.
* `pg_config --sharedir` valait `/usr/share/postgresql/16` (le premier correctif écrivait au mauvais endroit).
* **Correctif :** image `postgres:16-bookworm` + `postgresql-16-pgaudit`, configuration écrite dans
  `$(pg_config --sharedir)/postgresql.conf.sample`, `USER postgres`.
* **Preuve :** `SHOW shared_preload_libraries` → `pgaudit` ; `pg_extension` → `pgaudit 16.1` ;
  1 443 entrées `AUDIT:` (DDL/WRITE avec paramètres) dans les journaux du conteneur.

### D4 — Repli PBKDF2 (corrigé)
* `security.py` contenait une voie de repli `$pbkdf2-sha256$` si Argon2 manquait : downgrade silencieux
  contraire à RFC 9106 / OWASP ASVS V2.4.1. Vérifié : **0 occurrence** de `pbkdf2` dans le fichier.

---

## 5. Points ouverts (non bloquants pour l'Étape 1)

| ID | Sévérité | Description | Recommandation |
| :--- | :--- | :--- | :--- |
| **D5** | 🟡 | `HS256` statique, pas de JWKS ni de rotation de clé. | Étape 3 : passer en RS256/EdDSA + `/.well-known/jwks.json` + `kid` + double clé active. |
| **D6** | 🟠 | `time_between` retombe sur `datetime.now()` si `environment.time` est absent → **non fail-closed**. | Supprimer le repli : attribut absent ⇒ condition fausse (deny). |
| **D7** | 🟡 | La matrice annonce `PLANT_MANAGER` en lecture de `sec_data.users` ; aucun `GRANT` n'existe. | Trancher (doc ou grant) et aligner. |
| — | 🟡 | Le PDP ABAC n'est branché sur **aucune route** (seules les gardes RBAC le sont). | Étape 2/3 : PEP `require_abac(action, urn)` alimentant le contexte depuis la requête + la BDD. |

---

## 6. Ce qui n'a pas été validé

* **Charge / performance** : aucun test de montée en charge (hors périmètre Étape 1).
* **Front React, SIEM, IaC** : Étapes 4 à 7.
* **Rotation de clé de chiffrement TDE** : le service lit une clé unique ; la rotation (versioning de
  clé, ré-chiffrement) n'est pas implémentée.
* **mTLS** : l'extraction du certificat client est prête (`X-SSL-Client-SHA256`), mais la terminaison
  TLS mutuelle n'est pas déployée (Étape 2, Edge Gateway).

---

## 7. Procédure de reproductibilité

```bash
# 1. Base durcie (pgAudit inclus)
cd infra/docker && docker compose up -d --build

# 2. Migrations (baseline + seed IAM/ABAC + correctifs)
cd database/migrations
../../services/backend-api/.venv/bin/alembic -c alembic.ini upgrade head

# 3. Suite complète + couverture
services/backend-api/.venv/bin/python -m pytest -q --cov=services/backend-api/app

# 4. Portes qualité
cd services/backend-api
.venv/bin/mypy --strict app
.venv/bin/black --check app ../../tests
.venv/bin/bandit -q -r app -ll

# 5. Preuve pgAudit
docker exec securiglass-postgres psql -U securiglass_admin -d securiglass_db \
  -tAc "show shared_preload_libraries; select extversion from pg_extension where extname='pgaudit';"
docker logs securiglass-postgres 2>&1 | grep -c "AUDIT:"
```
