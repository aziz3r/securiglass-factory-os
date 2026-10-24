# 📖 Dictionnaire de Données - SecuriGlass Factory OS (Étape 1)

Ce dictionnaire spécifie l'ensemble des schémas PostgreSQL segmentés conformément aux exigences IEC 62443 et ISA-95 (Purdue).

---

## 1. Schéma `sec_data` (Gestion des Identités, Accès & Audit)
**Objectif :** Héberger les utilisateurs, rôles, permissions, politiques ABAC dynamiques, sessions et pistes d'audit immuables.

| Table | Colonne | Type | Nullable | Contraintes / Format | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`users`** | `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant unique de l'utilisateur |
| | `username` | `VARCHAR(64)` | NON | UNIQUE, Index | Nom d'utilisateur (alphanumérique + `._-`) |
| | `email` | `VARCHAR(255)` | NON | UNIQUE, Index | Adresse email professionnelle normalisée |
| | `password_hash` | `TEXT` | NON | Hash Argon2id (`$argon2id$...`) | Hash de passeport sécurisé Argon2id |
| | `salt` | `VARCHAR(64)` | NON | Hex/Base64 aléatoire 32 octets | Sel cryptographique crypté |
| | `clearance_level` | `SMALLINT` | NON | DEFAULT 1, CHECK (1 à 5) | Niveau d'habilitation sécurité (1=Opérateur, 5=SuperAdmin) |
| | `is_active` | `BOOLEAN` | NON | DEFAULT TRUE | Indicateur de compte actif/inactif |
| | `is_mfa_enabled` | `BOOLEAN` | NON | DEFAULT FALSE | Indique si le TOTP/FIDO2 est requis |
| | `mfa_secret_encrypted` | `BYTEA` | OUI | Chiffré AES-256-GCM / KMS | Clé secrète TOTP chiffrée |
| | `failed_login_attempts` | `SMALLINT` | NON | DEFAULT 0 | Compteur d'échecs pour blocage anti-bruteforce |
| | `locked_until` | `TIMESTAMPTZ` | OUI | NULL si non verrouillé | Date limite de verrouillage du compte |
| | `created_at` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Date de création |
| | `updated_at` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Dernière mise à jour |
| **`roles`** | `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant unique du rôle |
| | `role_code` | `VARCHAR(32)` | NON | UNIQUE | Code standard (`SUPER_ADMIN`, `PLANT_MANAGER`, etc.) |
| | `name` | `VARCHAR(64)` | NON | - | Nom lisible du rôle |
| | `description` | `TEXT` | OUI | - | Descriptif des prérogatives |
| | `default_clearance`| `SMALLINT` | NON | DEFAULT 1 | Niveau d'accréditation requis par défaut |
| **`permissions`** | `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant unique de la permission |
| | `perm_code` | `VARCHAR(64)` | NON | UNIQUE, Format `module:action` | Ex: `ot:furnace:read`, `it:orders:write` |
| | `module` | `VARCHAR(32)` | NON | - | Module fonctionnel (`OT`, `IT`, `SEC`, `SOC`) |
| | `description` | `TEXT` | OUI | - | Intitulé explicite de l'autorisation |
| **`user_roles`** | `user_id` | `UUID` | NON | FK -> `users(id)` ON DELETE CASCADE | Clé composite (user_id, role_id) |
| | `role_id` | `UUID` | NON | FK -> `roles(id)` ON DELETE RESTRICT | |
| | `assigned_at` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Date d'affectation |
| | `assigned_by` | `UUID` | OUI | FK -> `users(id)` | Administrateur ayant conféré le rôle |
| **`role_permissions`**| `role_id` | `UUID` | NON | FK -> `roles(id)` ON DELETE CASCADE | Clé composite (role_id, permission_id) |
| | `permission_id`| `UUID` | NON | FK -> `permissions(id)` ON DELETE CASCADE| |
| **`abac_policies`**| `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant de la politique ABAC |
| | `policy_name` | `VARCHAR(64)` | NON | UNIQUE | Nom de la règle d'autorisation contextuelle |
| | `effect` | `VARCHAR(8)` | NON | CHECK `effect IN ('ALLOW', 'DENY')`| Décision de conformité |
| | `subject_role`| `VARCHAR(32)` | NON | - | Rôle assujetti ou `*` |
| | `action_verb` | `VARCHAR(32)` | NON | Ex: `READ`, `WRITE`, `EXECUTE` | Verbe d'action visé |
| | `resource_urn`| `VARCHAR(128)`| NON | Ex: `urn:securiglass:ot:line_01:control`| Ressource protégée |
| | `rule_condition`| `JSONB` | NON | Expression JSONB stricte | Critères (IP CIDR, Plages horaires, Cert mTLS) |
| **`audit_logs`** | `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant unique du log d'audit |
| | `event_time` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Horodatage à la microseconde |
| | `event_type` | `VARCHAR(64)` | NON | - | Ex: `AUTH_LOGIN`, `FURNACE_SETPOINT_CHANGE` |
| | `actor_id` | `UUID` | OUI | FK -> `users(id)` | Acteur de l'action (NULL si service externe) |
| | `actor_username`| `VARCHAR(64)`| NON | - | Identifiant textuel préservé en cas de purge |
| | `actor_ip` | `INET` | NON | Format IPv4 / IPv6 valide | Adresse IP source |
| | `client_cert_fingerprint`| `VARCHAR(64)`| OUI | SHA-256 du certificat client mTLS | Empreinte mTLS de la source |
| | `action` | `VARCHAR(32)` | NON | Ex: `READ`, `CREATE`, `UPDATE`, `EXEC`| Action menée |
| | `resource` | `VARCHAR(128)`| NON | - | Cible de l'action |
| | `outcome` | `VARCHAR(16)` | NON | CHECK `outcome IN ('SUCCESS','DENIED','FAILURE')` | Résultat de l'accès |
| | `details` | `JSONB` | OUI | - | Détails techniques et contexte |
| | `prev_log_hash`| `CHAR(64)` | OUI | SHA-256 du log précédent | Chaînage cryptographique anti-falsification |
| | `current_hash`| `CHAR(64)` | NON | SHA-256(row data + prev_hash) | Empreinte d'intégrité de la ligne |
| **`token_revocations`**| `jti` | `UUID` | NON | PK | JWT ID révoqué avant expiration |
| | `user_id` | `UUID` | NON | FK -> `users(id)` | Propriétaire du token révoqué |
| | `revoked_at` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Date d'invalidation |
| | `expires_at` | `TIMESTAMPTZ` | NON | - | Date d'expiration nominale du token |
| | `reason` | `VARCHAR(128)`| OUI | - | Cause (ex: `LOGOUT`, `PASSWORD_CHANGE`, `BREACH`)|

---

## 2. Schéma `it_data` (Gestion Industrielle & Commandes Métier - Niveau 4)
**Objectif :** Gestion des clients, commandes de verres sécurisés, ordonnancement des lots et recettes de trempe. Données sensibles soumises au RGPD avec TDE.

| Table | Colonne | Type | Nullable | Contraintes / Format | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`customers`** | `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant du client |
| | `company_name` | `VARCHAR(128)` | NON | Index | Dénomination sociale |
| | `contact_name_encrypted` | `BYTEA` | NON | Chiffrement TDE / AES-256-GCM | Nom du contact B2B (Donnée Personnelle) |
| | `email_encrypted` | `BYTEA` | NON | Chiffrement TDE / AES-256-GCM | Email du contact (Donnée Personnelle) |
| | `phone_encrypted` | `BYTEA` | OUI | Chiffrement TDE / AES-256-GCM | Téléphone direct (Donnée Personnelle) |
| | `vat_number` | `VARCHAR(32)` | OUI | - | Numéro de TVA intracommunautaire |
| | `country_code` | `CHAR(2)` | NON | Code ISO 3166-1 alpha-2 | Pays |
| | `is_active` | `BOOLEAN` | NON | DEFAULT TRUE | Statut commercial |
| | `created_at` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Date de création |
| **`recipes`** | `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant unique de la recette de trempe |
| | `recipe_code` | `VARCHAR(32)` | NON | UNIQUE | Code recette (ex: `RECIPE_TEMPER_8MM_ARCH`) |
| | `name` | `VARCHAR(96)` | NON | - | Libellé commercial de la spécification |
| | `glass_type` | `VARCHAR(32)` | NON | CHECK (enum type de verre) | Type (`FLOAT_TEMPERED`, `LAMINATED_SEC`, etc.) |
| | `thickness_nominal_mm`| `NUMERIC(4,1)`| NON | CHECK (`thickness_nominal_mm > 0`) | Épaisseur nominale en mm (ex: 8.0, 12.0) |
| | `target_furnace_temp_c`| `NUMERIC(5,1)`| NON | CHECK (entre 600 et 750 °C) | Consigne température four de trempe |
| | `target_quench_pressure_bar`| `NUMERIC(4,2)`| NON | CHECK (entre 0.5 et 10.0 bar) | Pression du caisson de trempe d'air |
| | `heating_duration_s` | `INTEGER` | NON | CHECK (`heating_duration_s > 0`) | Durée de séjour dans le four (secondes) |
| | `cooling_duration_s` | `INTEGER` | NON | CHECK (`cooling_duration_s > 0`) | Durée de trempe / refroidissement |
| | `version` | `INTEGER` | NON | DEFAULT 1 | Numéro de version de la recette |
| | `is_approved` | `BOOLEAN` | NON | DEFAULT FALSE | Validation stricte par la Métrologie / Qualité |
| | `approved_by` | `UUID` | OUI | FK -> `sec_data.users(id)` | Métrologue validateur |
| **`glass_orders`** | `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant de commande |
| | `order_ref` | `VARCHAR(32)` | NON | UNIQUE, Index | Réf commerciale (ex: `CMD-2026-0042`) |
| | `customer_id` | `UUID` | NON | FK -> `customers(id)` | Client donneur d'ordre |
| | `recipe_id` | `UUID` | NON | FK -> `recipes(id)` | Recette de fabrication assignée |
| | `width_mm` | `NUMERIC(6,1)`| NON | CHECK (`width_mm >= 100`) | Largeur du panneau de verre (mm) |
| | `height_mm` | `NUMERIC(6,1)`| NON | CHECK (`height_mm >= 100`) | Hauteur du panneau de verre (mm) |
| | `quantity` | `INTEGER` | NON | CHECK (`quantity > 0`) | Nombre de volumes commandés |
| | `status` | `VARCHAR(24)` | NON | DEFAULT `'SUBMITTED'` | Statut du cycle de vie |
| | `target_date` | `DATE` | NON | - | Date de livraison contractuelle |
| | `created_at` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Date d'enregistrement |
| **`production_batches`**| `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant de lot de production |
| | `batch_code` | `VARCHAR(32)` | NON | UNIQUE, Index | Numéro de lot usine (ex: `BATCH-2026-F1-018`) |
| | `order_id` | `UUID` | NON | FK -> `glass_orders(id)` | Commande liée |
| | `line_code` | `VARCHAR(32)` | NON | Référence ligne de trempe | Ligne de fabrication planifiée |
| | `planned_quantity` | `INTEGER` | NON | CHECK (`planned_quantity > 0`)| Quantité programmée |
| | `produced_quantity`| `INTEGER` | NON | DEFAULT 0 | Quantité conforme usinée |
| | `scrapped_quantity`| `INTEGER` | NON | DEFAULT 0 | Quantité rebutée pour non-conformité |
| | `status` | `VARCHAR(24)` | NON | DEFAULT `'PLANNED'` | Statut (`PLANNED`, `IN_RUN`, `DONE`, `HALTED`) |
| | `started_at` | `TIMESTAMPTZ` | OUI | - | Date/Heure de premier passage au four |
| | `finished_at`| `TIMESTAMPTZ` | OUI | - | Date/Heure de clôture du lot |

---

## 3. Schéma `ot_data` (Télémétrie Lignes & Contrôle Procédé - Niveaux 1-3)
**Objectif :** Télémétrie haute fréquence (Four de trempe, Autoclave de feuilletage, Contrôle qualité optique). Cloisonné, alimenté par la Data Diode / Gateway Edge.

| Table | Colonne | Type | Nullable | Contraintes / Format | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`production_lines`**| `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant de la ligne |
| | `line_code` | `VARCHAR(32)` | NON | UNIQUE | Code machine (ex: `FURNACE_LINE_ALPHA`) |
| | `line_name` | `VARCHAR(64)` | NON | - | Nom complet |
| | `purdue_level`| `SMALLINT` | NON | DEFAULT 2, CHECK (1 à 3) | Niveau ISA-95 affecté |
| | `ip_gateway` | `INET` | NON | IP dans le réseau OT DMZ | Adresse de la Gateway Edge associée |
| | `status` | `VARCHAR(24)` | NON | DEFAULT `'OFFLINE'` | État opérationnel (`RUNNING`, `MAINT`, `HALT`) |
| **`furnace_telemetry`**| `id` | `BIGSERIAL` | NON | PK composite avec `timestamp` | Identifiant incrémental |
| | `timestamp` | `TIMESTAMPTZ` | NON | Partitions mensuelles | Date et heure précise de l'échantillon |
| | `line_id` | `UUID` | NON | FK -> `production_lines(id)` | Ligne concernée |
| | `batch_id` | `UUID` | OUI | Référence batch sans FK bloquante | Lot en cours de chauffe |
| | `temp_zone1_c`| `NUMERIC(5,1)`| NON | CHECK (entre 0 et 850 °C) | Température Zone 1 d'enfournement (°C) |
| | `temp_zone2_c`| `NUMERIC(5,1)`| NON | CHECK (entre 0 et 850 °C) | Température Zone 2 centrale (°C) |
| | `temp_zone3_c`| `NUMERIC(5,1)`| NON | CHECK (entre 0 et 850 °C) | Température Zone 3 centrale (°C) |
| | `temp_zone4_c`| `NUMERIC(5,1)`| NON | CHECK (entre 0 et 850 °C) | Température Zone 4 sortie (°C) |
| | `glass_pyrometer_temp_c`| `NUMERIC(5,1)`| NON | CHECK (entre 0 et 850 °C) | Pyromètre optique infra-rouge surface verre |
| | `quench_pressure_bar` | `NUMERIC(4,2)`| NON | CHECK (entre 0 et 12 bar) | Pression d'air de soufflage de trempe |
| | `conveyor_speed_m_min` | `NUMERIC(4,2)`| NON | CHECK (entre 0 et 50 m/min) | Vitesse d'avance rouleaux céramiques |
| | `blower_current_amps` | `NUMERIC(5,1)`| NON | - | Consommation moteur soufflerie haute pression |
| | `power_consumption_kw`| `NUMERIC(6,2)`| NON | - | Puissance électrique totale instantanée |
| | `emergency_stop_tripped`| `BOOLEAN` | NON | DEFAULT FALSE | Arrêt d'urgence automate déclenché |
| | `plc_status_flags` | `INTEGER` | NON | DEFAULT 0 | Registre de drapeaux d'état automate |
| **`autoclave_telemetry`**| `id` | `BIGSERIAL`| NON | PK composite avec `timestamp` | Identifiant incrémental |
| | `timestamp` | `TIMESTAMPTZ` | NON | Partitions mensuelles | Date et heure précise de l'échantillon |
| | `line_id` | `UUID` | NON | FK -> `production_lines(id)` | Ligne autoclave |
| | `batch_id` | `UUID` | OUI | - | Lot feuilleté sous vide |
| | `vessel_pressure_bar` | `NUMERIC(4,2)`| NON | CHECK (entre 0 et 16 bar) | Pression cuve autoclave |
| | `vessel_temp_c` | `NUMERIC(5,1)`| NON | CHECK (entre 0 et 200 °C) | Température de cycle PVB |
| | `vacuum_bag_level_mbar`| `NUMERIC(5,1)`| NON | CHECK (entre 0 et 1013 mbar) | Dépression sac sous vide |
| | `cycle_phase` | `VARCHAR(24)` | NON | Ex: `VACUUM`, `HEATING`, `COOLING` | Phase du cycle |
| **`quality_defects`** | `id` | `UUID` | NON | PK, `gen_random_uuid()` | Identifiant du défaut |
| | `timestamp` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Détection par le scanner optique |
| | `batch_id` | `UUID` | OUI | - | Lot associé |
| | `line_id` | `UUID` | NON | FK -> `production_lines(id)` | Ligne de trempe |
| | `defect_type`| `VARCHAR(32)` | NON | CHECK (enum défauts) | Type (`ROLLER_WAVE`, `NICKEL_SULFIDE`, etc.)|
| | `severity` | `VARCHAR(16)` | NON | CHECK `severity IN ('LOW','MEDIUM','CRITICAL')` | Gravité du défaut |
| | `coord_x_mm` | `NUMERIC(6,1)`| NON | - | Position horizontale sur le vitrage (mm) |
| | `coord_y_mm` | `NUMERIC(6,1)`| NON | - | Position verticale sur le vitrage (mm) |
| | `action_taken`| `VARCHAR(24)`| NON | CHECK `action_taken IN ('REJECTED','FLAGGED','ACCEPTED')`| Décision automatique / manuelle |
| **`diode_import_log`**| `id` | `UUID` | NON | PK, `gen_random_uuid()` | Traçabilité de la Data Diode |
| | `transmission_id` | `UUID` | NON | UNIQUE | Identifiant unique de transmission émis |
| | `source_gateway` | `VARCHAR(64)` | NON | - | Nom de l'Edge Gateway émettrice |
| | `records_ingested` | `INTEGER` | NON | - | Nombre de mesures télémétriques reçues |
| | `packet_sha256` | `CHAR(64)` | NON | - | Checksum SHA-256 du paquet reçu |
| | `ed25519_signature`| `TEXT` | NON | - | Signature cryptographique de la passerelle OT |
| | `verified_at` | `TIMESTAMPTZ` | NON | DEFAULT `CURRENT_TIMESTAMP` | Horodatage de validation cryptographique |
