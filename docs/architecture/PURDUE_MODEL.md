# 🏭 Architecture ISA-95 / Modèle de Purdue - SecuriGlass Factory OS

## 1. Cartographie des Niveaux de Purdue (Zonage Sécurisé IEC 62443)

```
+-------------------------------------------------------------------------------+
|  NIVEAU 5 : Enterprise & SOC / Cloud                                          |
|  - SOC Industriel (Wazuh / ELK / Suricata)                                   |
|  - Postes analystes Cyber & Dashboard Web Central                             |
+-------------------------------------------------------------------------------+
                                    ▲  (HTTPS / WSS / mTLS)
                                    ▼
+-------------------------------------------------------------------------------+
|  NIVEAU 4 : Enterprise IT (Réseau d'Entreprise)                              |
|  - API Gateway & Backend FastAPI (OAuth2 / OIDC / Argon2id / ABAC)           |
|  - PostgreSQL Database (Schémas cloisonnés : sec_data, it_data, ot_data)      |
|  - RAG Sécurisé avec LLM Guard Sandbox                                       |
|  - Frontend SPA React (CSP default-src 'none', Zustand)                       |
+-------------------------------------------------------------------------------+
                                    ▲
                         [ iDMZ / Niveau 3.5 ]
      ┌───────────────────────────────────────────────────────────┐
      │  - Proxy Inverse mTLS Stricte                             │
      │  - Data Diode Logique Unidirectionnelle (OT ──► IT seul)  │
      │  - Broker MQTTS DMZ Cloisonné                             │
      └───────────────────────────────────────────────────────────┘
                                    ▲ (Télémétrie OT Unidirectionnelle)
                                    │ (AUCUN FLUX ENTRANT DIRECT IT -> OT)
+-------------------------------------------------------------------------------+
|  NIVEAU 3 : Manufacturing Operations Management (MOM / MES)                   |
|  - OT Historian / Influx-Postgres Bridge                                      |
|  - Moteur ML Anomaly Detection (Isolation Forest temps réel)                  |
|  - Station de Supervision Locale                                              |
+-------------------------------------------------------------------------------+
                                    ▲  (MQTTS / Modbus TCP)
                                    ▼
+-------------------------------------------------------------------------------+
|  NIVEAU 2 : Area Supervisory Control (Supervision Ligne)                     |
|  - OT Edge Gateway (Python Asyncio / Validation trames Modbus & MQTTS)       |
|  - HMI / IHM durcie locale (Read-Only)                                       |
+-------------------------------------------------------------------------------+
                                    ▲  (Modbus TCP durci / Bus de Terrain)
                                    ▼
+-------------------------------------------------------------------------------+
|  NIVEAU 1 : Basic Control (Automates & Contrôleurs)                           |
|  - Démon Automate C (Simulation PLC Four de Trempe & Autoclave)               |
|  - Gestion mémoire stricte (Zero leak Valgrind, POSIX C11)                   |
+-------------------------------------------------------------------------------+
                                    ▲  (I/O Tor, 4-20mA, PT100, RS485)
                                    ▼
+-------------------------------------------------------------------------------+
|  NIVEAU 0 : Processus Physique (Ligne de Verre Sécurit)                       |
|  - Four de Trempe (Zones de chauffe 650°C-720°C, Souffleries de Trempe)      |
|  - Autoclave Feuilletage (Pression 12 bars, 140°C)                            |
|  - Découpeuse Laser & Convoyeurs à rouleaux                                  |
|  - Scanners optiques de contraintes mécaniques                                |
+-------------------------------------------------------------------------------+
```

## 2. Règles Fondamentales d'Inter-Zonage
1. **Cloisonnement Strict :** Aucun équipement de Niveau 1 ou 2 ne communique directement avec le Niveau 4 ou 5.
2. **Data Diode Logique :** La transmission de télémétrie entre Niveau 3 et Niveau 4 traverse obligatoirement l'iDMZ (Niveau 3.5) en mode push unidirectionnel.
3. **Zero Trust & mTLS :** Tout échange interne fait l'objet d'une authentification mutuelle par certificats X.509 (mTLS) avec vérification de révocation CRL/OCSP.
4. **Cloisonnement des Données :** Les bases de données segmentent strictement les données de sécurité (`sec_data`), de gestion IT (`it_data`) et d'usine OT (`ot_data`) avec des privilèges de rôles SQL mutuellement exclusifs.
