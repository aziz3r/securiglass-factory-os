# Registre d'incidents — Blue Team SecuriGlass

> **Modèle de registre**. Les deux lignes présentes dans
> [`incidents.csv`](incidents.csv) sont des **exemples de démonstration**
> (`[EXEMPLE]`), pas des incidents réels. Ne pas les utiliser comme preuve.
>
> **Confidentialité** : un registre rempli peut contenir des données
> personnelles (RGPD) et des informations sensibles OT. Le stocker dans un
> espace à accès restreint, chiffré au repos, avec une piste d'audit des accès.

## 1. Objectif

Tracer de bout en bout chaque incident de sécurité détecté sur le périmètre
SecuriGlass (IT, IAM, audit, OT/Purdue 1-3, SOC), de la détection à la clôture,
conformément à :

* **IEC 62443-2-1** : procédure de réponse aux incidents et amélioration continue ;
* **IEC 62443-3-3 SR 6.1** : journalisation et preuve ;
* **RGPD art. 33/34** : notification de violation sous 72 h si données personnelles ;
* **MITRE ATT&CK for ICS** : qualification tactique/technique.

## 2. Cycle de vie

| Étape | Contenu | Sortie |
| :--- | :--- | :--- |
| 1. Détection | Alerte SIEM, signalement opérateur, audit, YARA, revue | `date_detection_utc`, `source_detection` |
| 2. Triage | Qualification, gravité, périmètre, faux positif | `severite`, `statut`, `regle_detection` |
| 3. Confinement | Isolation réseau, révocation JTI/certificat, arrêt de ligne si sûreté | `confinement` |
| 4. Éradication | Correctif, rotation de secrets, blocage | `eradication` |
| 5. Restauration | Remise en service contrôlée, vérification d'intégrité | `restauration` |
| 6. Leçons | Cause racine, nouvelles règles, mise à jour du registre | `commentaires`, nouvelles règles Sigma |

### Gravité et délais cibles

| Niveau | Exemple | Prise en charge | Clôture cible |
| :--- | :--- | :--- | :--- |
| **P1 — Critique** | Écriture hors horaire sur le four, chaîne d'audit rompue, certificat edge révoqué accepté | 15 min, astreinte 24/7 | 4 h |
| **P2 — Majeur** | Force brute suivie de succès, exfiltration clients, modification ABAC | 1 h ouvrée | 24 h |
| **P3 — Modéré** | Refus RBAC répétés, FIM sur binaire système | 4 h ouvrées | 5 jours |
| **P4 — Mineur** | Erreur de configuration, faux positif documenté | 1 jour ouvré | 30 jours |

## 3. Champs du registre

| Champ CSV | Obligatoire | Description |
| :--- | :--- | :--- |
| `incident_id` | Oui | `INC-AAAA-NNN`, unique, jamais réutilisé |
| `date_detection_utc` | Oui | ISO 8601 UTC (`2026-10-24T18:05:00Z`) |
| `titre` | Oui | Résumé factuel, sans jugement |
| `source_detection` | Oui | Wazuh (ID de règle), Sigma, YARA, opérateur, audit |
| `zone_purdue` | Oui | 0–5, ou `IT`, `DMZ`, `SOC` |
| `severite` | Oui | `P1` à `P4` |
| `statut` | Oui | `NOUVEAU`, `TRIAGE`, `CONFINE`, `ERADIQUE`, `RESTAURE`, `CLOTURE`, `FAUX_POSITIF` |
| `tactique_mitre` | Oui | Tactique ATT&CK ICS (ou Enterprise signalée) |
| `technique_mitre` | Oui | Nom de la technique |
| `id_technique` | Oui | `T0836`, `T0872`, … |
| `regle_detection` | Oui | ID Wazuh / fichier Sigma / règle YARA |
| `actif_concerne` | Oui | Hôte, automate, gateway, service, compte (sans secret) |
| `preuve` | Oui | Référence au journal/PCAP/hash, jamais le secret lui-même |
| `confinement` | Non | Mesure immédiate (isolation, révocation, arrêt) |
| `eradication` | Non | Correctif, rotation, blocage |
| `restauration` | Non | Remise en service, contrôle d'intégrité |
| `notification_rgpd` | Non | `OUI` / `NON` / `A_EVALUER` + date |
| `responsable` | Oui | Rôle (pas de nom personnel si évitable) |
| `date_cloture_utc` | Non | ISO 8601 UTC |
| `commentaires` | Non | Cause racine, leçons, liens |

## 4. Règles de tenue

1. **Un incident = une ligne** ; les mises à jour horodatées vont dans
   `commentaires` (ou un journal d'audit séparé).
2. **Heures en UTC** ; préciser la timezone dans les commentaires si une source
   locale est utilisée.
3. **Preuves** : conserver les journaux bruts dans un coffre en lecture seule,
   calculer un SHA-256 à la collecte, ne jamais modifier l'original.
4. **Données personnelles** : minimiser, pseudonymiser les comptes dans les
   exports larges, appliquer la durée de conservation RGPD.
5. **Chaîne de custody** : qui, quand, quel fichier, quel hash, quel support.
6. **Faux positif** : ne pas supprimer la ligne ; statut `FAUX_POSITIF` +
   justification + règle à ajuster.

## 5. Exemples de démonstration

| ID | Titre | Gravité | Statut | Détection |
| :--- | :--- | :--- | :--- | :--- |
| INC-2026-001 | `[EXEMPLE]` Force brute puis succès sur `operator1` | P2 | CLOTURE | Wazuh 100110/100111, Sigma 001/003 |
| INC-2026-002 | `[EXEMPLE]` Écriture Modbus hors horaire sur le four | P1 | EN COURS | Wazuh 100123, Sigma 006 |

Les lignes complètes sont dans [`incidents.csv`](incidents.csv).

## 6. Intégration avec les règles

| Détection | Règle | Réflexe de triage |
| :--- | :--- | :--- |
| Force brute | Wazuh 100110 | Vérifier la source, le compte, l'éventuel succès 100111 |
| Chaîne d'audit rompue | Wazuh 100106 | Geler la base, comparer `prev_log_hash`/`current_hash`, alerter le RSSI |
| ABAC modifié | Wazuh 100115/100116 | Comparer avec `sec_data.abac_policies`, vérifier l'auteur et le changement |
| Modbus non-OT | Wazuh 100121 | Identifier le port source, la gateway, l'outil ; isoler le poste |
| Écriture hors horaire | Wazuh 100123 | Vérifier la consigne, la télémesure, l'état du four ; envisager l'arrêt |
| Certificat révoqué | Wazuh 100124 | Révoquer la session, inspecter la gateway, rotation de clé |
| Exfiltration clients | Wazuh 100120/100129 | Qualifier le volume, le rôle, la destination ; RGPD 72 h |

## 7. Après l'incident

* Ajouter une règle Sigma/Wazuh si la détection était absente.
* Ajouter un cas de test dans `siem/tests/` ou `redteam/tests/`.
* Mettre à jour la cartographie `siem/ATTACK_ICS_MAPPING.md`.
* Planifier un exercice de rejeu (tabletop ou Red Team) et consigner les écarts.
