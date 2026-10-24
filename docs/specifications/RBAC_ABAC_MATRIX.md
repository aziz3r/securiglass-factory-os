# 🛡️ Matrice de Contrôle d'Accès Stricte (RBAC / ABAC) - SecuriGlass Factory OS

Conforme aux référentiels **IEC 62443-3-3** (System security requirements and security levels) et **OWASP ASVS 4.0 - V4 (Access Control Verification)**.

---

## 1. Rôles et Niveaux d'Habilitation (Clearance Levels)

| Identifiant Rôle | Code Rôle | Clearance | Périmètre & Description |
| :--- | :--- | :---: | :--- |
| `ROLE_SUPER_ADMIN` | `SUPER_ADMIN` | **5** | Administration système & sécurité, gestion des identités, révocation des accès. Interdiction de falsifier les logs d'audit. |
| `ROLE_SEC_AUDITOR` | `SECURITY_AUDITOR` | **4** | Audit de conformité, consultation immuable des journaux d'audit et politiques d'accès. Aucun droit d'altération opérationnelle. |
| `ROLE_PLANT_MGR` | `PLANT_MANAGER` | **3** | Gestion de l'usine, planification des ordres de production, validation formelle des recettes thermiques. |
| `ROLE_OT_OPERATOR` | `OT_OPERATOR` | **2** | Conduite des lignes de trempe et autoclaves, visualisation télémétrique temps réel, acquittement d'alertes process. |
| `ROLE_QUALITY_INSP` | `QUALITY_INSPECTOR` | **2** | Contrôle optique et géométrique, enregistrement des défauts matière, qualification/rebut des lots. |
| `ROLE_EDGE_SERVICE`| `SERVICE_ACCOUNT_EDGE`| **2** | Compte de service machine-to-machine (Edge Gateway / Data Diode). Strictement restreint à l'insertion de télémétrie. |

---

## 2. Matrice d'Accès aux Données (RBAC Tabulaire)

Légende : **C** = Create / Insert, **R** = Read / Select, **U** = Update, **D** = Delete, **-** = Aucun accès (Deny implicite).

| Schéma / Ressource | `SUPER_ADMIN` | `SECURITY_AUDITOR` | `PLANT_MANAGER` | `OT_OPERATOR` | `QUALITY_INSPECTOR` | `SERVICE_ACCOUNT_EDGE` |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **`sec_data.users`** | C R U D | R | R (filtré usine) | - | - | - |
| **`sec_data.roles_perm`** | C R U D | R | - | - | - | - |
| **`sec_data.abac_policies`** | C R U D | R | - | - | - | - |
| **`sec_data.audit_logs`** | R (Append-Only) | R (Append-Only) | - | - | - | - |
| **`sec_data.token_revoc`** | C R | R | - | - | - | - |
| **`it_data.customers`** | R | R | C R U | - | - | - |
| **`it_data.recipes`** | R | R | C R U (Approuve) | R | R | - |
| **`it_data.glass_orders`** | R | R | C R U D | R | R | - |
| **`it_data.batches`** | R | R | C R U | R U (Statut) | R U (Scrap) | - |
| **`ot_data.production_lines`** | R U | R | R U | R | R | R |
| **`ot_data.furnace_telemetry`** | R | R | R | R | R | **C (Insert Seul)** |
| **`ot_data.autoclave_telemetry`** | R | R | R | R | R | **C (Insert Seul)** |
| **`ot_data.quality_defects`** | R | R | R | R | C R U | - |
| **`ot_data.diode_import_log`** | R | R | R | - | - | **C (Insert Seul)** |

> [!IMPORTANT]
> **Règle d'Append-Only Cryptographique :** Les tables `sec_data.audit_logs`, `ot_data.furnace_telemetry` et `ot_data.autoclave_telemetry` possèdent un trigger d'interdiction formelle sur `UPDATE` et `DELETE`. Aucun rôle, même `SUPER_ADMIN`, ne peut altérer ou effacer un enregistrement existant.

---

## 3. Politiques Dynamiques Basées sur les Attributs (ABAC - Attribute-Based Access Control)

Le moteur d'évaluation de politique (PEP/PDP) vérifie les attributs du sujet, de la ressource, de l'action et de l'environnement :

### Politique ABAC-01 : Cloisonnement Réseau de l'Opérateur OT (`ABAC_ENFORCE_OPERATOR_SUBNET`)
* **Sujet :** Tout utilisateur disposant du rôle `OT_OPERATOR`.
* **Action :** `ot:control:write`, `ot:recipe:select`, `it:batch:update_status`.
* **Condition :** 
  ```json
  {
    "and": [
      { "in_cidr": { "client_ip": "10.10.20.0/24" } },
      { "time_between": { "start": "05:45:00", "end": "22:15:00" } },
      { "equals": { "environment.maintenance_lock": false } }
    ]
  }
  ```
* **Effet :** `DENY` si le client n'est pas sur le sous-réseau de la salle de contrôle OT ou hors plage horaire.

### Politique ABAC-02 : Validation Cryptographique Edge Gateway / Data Diode (`ABAC_ENFORCE_EDGE_MTLS`)
* **Sujet :** Compte `SERVICE_ACCOUNT_EDGE`.
* **Action :** `ot:telemetry:insert`.
* **Condition :**
  ```json
  {
    "and": [
      { "in_cidr": { "client_ip": "10.10.30.0/24" } },
      { "equals": { "client_cert.issuer": "CN=SecuriGlass-OT-CA,O=SecuriGlass" } },
      { "equals": { "client_cert.san_dns": "edge-gateway.ot.local" } },
      { "not_in": { "client_cert.serial": "REVOKED_CERTS_LIST" } }
    ]
  }
  ```
* **Effet :** `DENY` absolu si la négociation mTLS échoue ou si le certificat ne correspond pas à l'empreinte matérielle de la Gateway.

### Politique ABAC-03 : Principe des Quatre Yeux sur les Recettes Thermiques (`ABAC_FOUR_EYES_RECIPE_APPROVAL`)
* **Sujet :** Rôle `PLANT_MANAGER`.
* **Action :** `it:recipe:approve`.
* **Condition :**
  ```json
  {
    "and": [
      { "not_equals": { "subject.user_id": "resource.recipe.created_by" } },
      { "greater_or_equal": { "subject.clearance_level": 3 } }
    ]
  }
  ```
* **Effet :** `DENY` si l'utilisateur tente d'approuver une recette thermique de trempe qu'il a lui-même créée (prévention d'erreur ou sabotage du four).

---

## 4. Spécifications Cryptographiques pour l'IAM
* **Algorithme de Hachage :** Argon2id (RFC 9106)
  * Mémoire (`m`) : 65 536 KiB (64 MiB)
  * Itérations (`t`) : 3 passes
  * Parallélisme (`p`) : 4 threads
  * Longueur de sel : 16 octets CSPRNG
* **Protection RGPD / TDE :** Chiffrement des colonnes identifiantes (`contact_name`, `email`, `phone`) via AES-256-GCM avec clé rotative gérée en variables d'environnement / Secret Manager.
