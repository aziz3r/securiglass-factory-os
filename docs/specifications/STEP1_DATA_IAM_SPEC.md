# 📐 Spécification Technique & Directives d'Implémentation - Étape 1 : Fondations Data & IAM

**Normes cibles :** OWASP ASVS v4.0 (Niveau 2+), IEC 62443-3-3, RGPD (Art. 32).

---

## 1. Périmètre Fonctionnel de l'Étape 1
Cette étape établit le socle cryptographique, l'infrastructure de données et le moteur d'habilitation (IAM) de l'usine SecuriGlass :
1. **Base de données PostgreSQL Durcie :** Schémas `sec_data`, `it_data`, `ot_data` segmentés, tables immuables pour la télémétrie et l'audit.
2. **Hachage Sécurisé Argon2id :** Implémentation stricte conforme RFC 9106.
3. **Moteur d'Habilitation RBAC / ABAC :** Évaluation contextuelle des requêtes (IP, horaires d'équipe, certificats mTLS).
4. **Protection des Données RGPD (TDE Applicatif) :** Chiffrement transparent AES-256-GCM des données personnelles clients.
5. **Chaîne de Confiance d'Audit :** Calcul automatique des empreintes SHA-256 chaînées anti-altération.

---

## 2. Directives d'implémentation (Backend)

### A. Emplacement du Code
Développer le service IAM dans le répertoire `services/backend-api/app/` :
* `app/core/config.py` : Configuration via Pydantic Settings (variables d'environnement strictes).
* `app/core/security.py` : Fonctions cryptographiques :
  * `hash_password(password: str) -> str` : Utiliser `argon2-cffi` avec `time_cost=3`, `memory_cost=65536`, `parallelism=4`, `salt_len=16`.
  * `verify_password(plain_password: str, hashed_password: str) -> bool`.
  * `encrypt_field(plaintext: str, key: bytes) -> bytes` : AES-256-GCM avec nonce 96 bits et tag d'authentification 128 bits.
  * `decrypt_field(ciphertext: bytes, key: bytes) -> str`.
  * `generate_jwt_token(payload: dict) -> str` et `verify_jwt_token(token: str) -> dict`.
* `app/services/abac_engine.py` : Moteur d'évaluation des politiques :
  * Évalue les conditions JSONB (`in_cidr`, `time_between`, `equals`).
  * Applique le principe "Default Deny".
* `app/services/audit_service.py` : Service d'enregistrement des logs avec chaînage SHA-256 du hash précédent.
* `app/api/` : Endpoints FastAPI sécurisés :
  * `POST /api/v1/auth/login` (avec protection contre bruteforce : verrouillage après 5 tentatives).
  * `POST /api/v1/auth/logout` (révocation via `token_revocations`).
  * `GET /api/v1/auth/me` (profil utilisateur, rôle et clearance).
  * `POST /api/v1/customers` (démonstration TDE AES-GCM sur données personnelles).
  * `GET /api/v1/audit/logs` (réservé `SUPER_ADMIN` et `SECURITY_AUDITOR`).

---

## 3. Directives de validation (DevSecOps & QA)

1. **Génération des Migrations :**
   * Configurer Alembic dans `database/migrations/` pour orchestrer les schémas DDL.
2. **Couverture de Tests (>85%) :**
   * `tests/unit/test_security_crypto.py` : Vérifier Argon2id, AES-256-GCM (résistance à la corruption du tag).
   * `tests/unit/test_abac_engine.py` : Tester l'ensemble des scénarios ABAC (accès hors plage horaire, IP interdite, rejet des opérateurs non-OT).
   * `tests/integration/test_rbac_matrix.py` : Valider les permissions SQL réelles face à la matrice définie dans `RBAC_ABAC_MATRIX.md`.
   * `tests/security/test_audit_chain_tamper.py` : Tenter d'injecter ou modifier une ligne d'audit et vérifier la détection de rupture de chaîne.
3. **Contrôle Qualité & Scan de Sécurité :**
   * Exécuter `mypy --strict` sur le code du backend.
   * Lancer Semgrep / Bandit sur le backend pour garantir 0 vulnérabilité.
