# Cartographie MITRE ATT&CK for ICS — SecuriGlass Factory OS

> **Périmètre** : Étape 2 (simulation OT : simulateur d'automate Modbus TCP sur
> `10.10.30.0/24`, port **5020**, gateway edge, salle de contrôle
> `10.10.20.0/24`) et Étape 1 (IAM, audit chaîné SHA-256, pgAudit).
>
> **Sources de détection** : flux d'audit applicatif SecuriGlass
> (`/var/log/securiglass/audit.jsonl`), journaux pgAudit
> (`/var/log/securiglass/postgresql.log`), EVE JSON Suricata
> (`/var/log/securiglass/suricata/eve.json`) et FIM Wazuh.
>
> **Règles** : Sigma (`siem/sigma/`), Wazuh locales (`siem/wazuh/rules/`,
> IDs ≥ 100000), YARA (`siem/yara/`).
>
> **Avertissement** : ce mapping est un artefact de conception. Il ne prouve
> pas que les règles ont déclenché sur une infrastructure réelle ; se référer
> à `siem/REPORT.md` pour le statut exact des vérifications.

## 1. Tableau de couverture

| Tactic (ATT&CK ICS) | Technique | ID | Détection associée | Règle(s) |
| :--- | :--- | :--- | :--- | :--- |
| Credential Access (Enterprise, pas d'équivalent ICS direct) | Brute Force: Password Guessing | **T1110.001** | ≥ 8 échecs `AUTH_LOGIN` depuis la même IP en 5 min ; verrouillage `account_locked` | Sigma [001](sigma/001_brute_force_auth.yml), [002](sigma/002_account_lockout.yml) — Wazuh `100110`, `100112` |
| Credential Access / Initial Access | Valid Accounts | **T0859** | Succès `AUTH_LOGIN` après ≥ 3 échecs (`details.prior_failures`) ; certificat edge révoqué | Sigma [003](sigma/003_success_after_failures.yml), [008](sigma/008_revoked_edge_certificate.yml) — Wazuh `100111`, `100124` |
| Defense Evasion | Indicator Removal on Host | **T0872** | Rupture de chaîne `AUDIT_CHAIN_INTEGRITY_CHECK` ; `UPDATE/DELETE` sur `sec_data.audit_logs` ; modification d'un manifeste scellé | Sigma [004](sigma/004_audit_chain_break.yml) — Wazuh `100106`, `100119`, `100127` |
| Persistence / Privilege Escalation | Account Manipulation (Enterprise **T1098**, pas d'équivalent ICS direct) | **T1098** | Modification d'une politique ABAC via l'API ou pgAudit ; changement de rôle PostgreSQL | Sigma [010](sigma/010_abac_policy_modification.yml) — Wazuh `100115`, `100116`, `100118` |
| Persistence / Lateral Movement | Valid Accounts | **T0859** | ≥ 5 refus `ACCESS_DENIED_RBAC` par utilisateur en 10 min ; ≥ 3 refus d'habilitation en 5 min | Sigma [005](sigma/005_repeated_rbac_denied.yml) — Wazuh `100113`, `100114` |
| Initial Access / Lateral Movement | Remote Services | **T0886** | Connexion Modbus/TCP 5020 dont la source n'est pas `10.10.30.0/24` | Sigma [007](sigma/007_modbus_from_non_ot_network.yml) — Wazuh `100121` |
| Discovery | Network Connection Enumeration | **T0840** | Connexions répétées vers le port 5020 depuis la salle de contrôle ou l'IT | Sigma [007](sigma/007_modbus_from_non_ot_network.yml) — Wazuh `100121` |
| Command and Control | Commonly Used Port | **T0885** | Usage du port 5020 hors zone OT (pivot, tunnel, outil de diagnostic) | Sigma [007](sigma/007_modbus_from_non_ot_network.yml) — Wazuh `100121` |
| Impair Process Control | Modify Parameter | **T0836** | Écriture Modbus FC5/6/15/16 hors zone OT ; écriture hors plage **05:45–22:15** ; registres critiques 0–9 | Sigma [006](sigma/006_ot_write_outside_schedule.yml) — Wazuh `100122`, `100123`, `100125`, `100128` |
| Impact | Manipulation of Control | **T0831** | Modification de consigne de trempe / pression / vitesse hors fenêtre de production | Sigma [006](sigma/006_ot_write_outside_schedule.yml) — Wazuh `100123`, `100125` |
| Impact | Damage to Property | **T0879** | Écriture hors horaire sur les zones du four (risque de casse verre, surchauffe) | Sigma [006](sigma/006_ot_write_outside_schedule.yml) — Wazuh `100123` |
| Impact | Loss of Protection | **T0837** | Tentative de contournement ABAC (certificat révoqué, hors CIDR, auto-approbation) | Sigma [008](sigma/008_revoked_edge_certificate.yml), [010](sigma/010_abac_policy_modification.yml) — Wazuh `100116`, `100124` |
| Collection | Data from Information Repositories | **T0811** | `CUSTOMER_LISTED` avec `details.record_count ≥ 1000` ; ≥ 10 consultations clients en 60 s | Sigma [009](sigma/009_customer_data_exfiltration.yml) — Wazuh `100120`, `100129` |
| Persistence (Enterprise) | Server Software Component: Web Shell (**T1505.003**) | **T1505.003** | Webshell PHP/JSP/ASP générique | YARA [`webshell_generic.yar`](yara/webshell_generic.yar) (scan fichier, pas SIEM) |
| Lateral Movement / Persistence | Modify Program | **T0889** | Binaire ELF/PE avec chaînes de debug OT + bibliothèque Modbus | YARA [`ot_suspicious_binary.yar`](yara/ot_suspicious_binary.yar) (scan fichier, pas SIEM) |
| Impair Process Control | Unauthorized Command Message | **T0855** | Trame Modbus d'écriture FC5/6/15/16 | YARA [`modbus_injection_payload.yar`](yara/modbus_injection_payload.yar) + Sigma [007](sigma/007_modbus_from_non_ot_network.yml) |

## 2. Couverture par tactique

| Tactique ICS | Techniques couvertes | Niveau de couverture |
| :--- | :--- | :--- |
| Initial Access | T0859, T0886 | Partiel (réseau + identité, pas de détection d'exploitation de firmware) |
| Execution | — | Non couvert (pas de télémétrie EDR sur les automates) |
| Persistence | T0859, T1098, T0889 (YARA) | Partiel |
| Privilege Escalation | T1098 | Partiel |
| Defense Evasion | T0872 | Bon sur la piste d'audit, faible sur les automates |
| Discovery | T0840 | Partiel (réseau uniquement) |
| Collection | T0811 | Bon sur l'export clients |
| Command and Control | T0885 | Partiel (port 5020) |
| Impair Process Control | T0836, T0855 | Bon sur Modbus, à compléter par la télémétrie four |
| Inhibit Response Function | — | Non couvert (T0878 Alarm Suppression, T0816 Device Restart) |
| Impact | T0831, T0837, T0879 | Partiel (détection d'écriture, pas de corrélation thermique) |

## 3. Techniques non couvertes et feuille de route

| Technique | ID | Raison | Contre-mesure prévue |
| :--- | :--- | :--- | :--- |
| Alarm Suppression | T0878 | Pas de collecte des journaux de l'automate ni de la supervision | Agent Wazuh sur la gateway + parsing des alarmes OPC UA / Modbus |
| Device Restart/Shutdown | T0816 | Absence de télémétrie de redémarrage PLC | Champ `plc_status_flags` et `emergency_stop_tripped` de `ot_data.furnace_telemetry` |
| Denial of Control | T0813 | Pas de mesure de disponibilité de la boucle de régulation | Supervision de heartbeat gateway + timeout Modbus |
| Manipulation of View | T0832 | Pas de comparaison redondante capteur/consigne | Corrélation `glass_pyrometer_temp_c` vs `temp_zone*` (Étape 3) |
| Program Download | T0843 | Pas de surveillance des téléchargements programme automate | Journal constructeur + FIM sur les projets PLC |
| Exploitation of Remote Services | T0866 | Pas de détection d'exploit au niveau automate | Suricata OT + signatures Modbus anormales |

## 4. Correspondance IEC 62443 (zones et conduits)

| Exigence / SR | Mesure SecuriGlass | Preuve |
| :--- | :--- | :--- |
| SR 1.1 — Identification et authentification | JWT/JTI, Argon2id, mTLS edge | `services/backend-api/app/core/security.py`, règles `100101`–`100112` |
| SR 1.2 — Gestion des identités et certificats | Révocation edge, certificat `REVOKED` | Règle `100124`, Sigma 008 |
| SR 2.1 — Contrôle d'accès | RBAC/ABAC default-deny, audit des refus | Règles `100104`–`100105`, `100113`–`100115` |
| SR 3.2 — Protection contre la modification malveillante | Chaîne SHA-256, trigger d'immuabilité, pgAudit | Règles `100106`, `100119`, Sigma 004 |
| SR 5.1 — Segmentation réseau | Zones Purdue 2/3, Modbus 5020 interdit hors OT | Sigma 007, règle `100121` |
| SR 6.1 — Journalisation | Audit applicatif + pgAudit + Wazuh | `ossec.conf` localfile, décodeurs |
| SR 7.1 — Disponibilité | Pas d'Active Response automatique sur l'OT | `ossec.conf` (aucune active-response) |

## 5. Limites de la cartographie

1. **Pas de corrélation physique** : une écriture Modbus hors horaire est
   détectée, mais le lien avec une dérive thermique réelle du four n'est pas
   encore modélisé (pas de jointure `ot_data.furnace_telemetry`).
2. **Horodatage** : la règle Wazuh `100123` utilise l'heure d'ingestion du
   manager (TZ `Europe/Paris`), pas l'horodatage de la trame. NTP obligatoire.
3. **Champs normalisés** : `details.prior_failures`, `outside_schedule` et
   `details.cert_status` doivent être émis par l'exportateur / la passerelle.
   Voir le contrat dans `siem/README.md`.
4. **ATT&CK ICS ≠ Enterprise** : T1110, T1098 et T1505.003 n'ont pas
   d'équivalent strict dans ATT&CK for ICS ; ils sont signalés comme
   « Enterprise » dans le tableau pour éviter toute confusion.
5. **YARA** n'est pas une règle SIEM : le scan est déclenché par un agent ou
   une tâche planifiée ; l'alerte doit être remontée dans Wazuh via un
   `localfile` dédié (non inclus dans ce PoC).
