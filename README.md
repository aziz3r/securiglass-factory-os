# SecuriGlass Factory OS

Console de supervision sécurisée pour une ligne de production de verre
trempé — preuve de concept (PoC) de cybersécurité industrielle (OT/IT),
conçue autour du modèle de Purdue, d'une diode de données unidirectionnelle,
d'un assistant IA protégé par quatre barrières de sûreté, et d'un journal
d'audit chaîné cryptographiquement.

**Auteur :** Mohamed Aziz Baoueb

> Ce dépôt est une démonstration technique, pas un produit industriel
> homologué. Les mesures marquées *planifiées* dans la documentation ne sont
> pas implémentées — voir [Limites connues](#limites-connues).

---

## Sommaire

- [Aperçu](#aperçu)
- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Pile technologique](#pile-technologique)
- [Démarrage rapide](#démarrage-rapide)
- [Comptes de démonstration](#comptes-de-démonstration)
- [Structure du dépôt](#structure-du-dépôt)
- [Sécurité](#sécurité)
- [Tests et qualité](#tests-et-qualité)
- [Documentation complète](#documentation-complète)
- [Limites connues](#limites-connues)

## Aperçu

Le projet simule, de bout en bout, la supervision numérique d'une ligne de
trempe de verre conforme à la norme **EN 12150-1** : un automate (écrit en C)
pilote un four à quatre zones de chauffe, une passerelle collecte ses mesures
en lecture seule, une diode de données les transmet à sens unique vers le
système d'information, où une API les expose à une console web par rôle,
avec un modèle d'apprentissage automatique qui surveille le four en continu
et un assistant conversationnel protégé contre les tentatives de
manipulation.

La chaîne tourne entièrement en local (Docker + processus natifs), sans
dépendance à un service cloud.

## Fonctionnalités

| Page | Ce qu'elle fait |
| --- | --- |
| **Accueil** | Résumé des indicateurs clés selon le rôle connecté. |
| **Production** | Température du four en direct (zone par zone), diagnostic d'anomalie par apprentissage automatique, jauges de température et de pression. |
| **Stocks** | Niveaux des six matières premières, alerte de réapprovisionnement. |
| **Commandes** | Prise de commande client ; déduit automatiquement les matières premières du stock dans une transaction atomique. |
| **Clients** | Fichier clients avec données personnelles chiffrées au repos (AES-256-GCM). |
| **Assistant technique** | Assistant RAG sur la norme EN 12150, protégé par quatre barrières contre l'injection de prompt et la fuite de données. |
| **Sécurité** | Note de conformité, flux d'alertes qualifiées MITRE ATT&CK, schéma de circulation des données OT↔IT. |
| **Journal d'audit** | Journal chaîné par empreintes SHA-256, avec vérification d'intégrité recalculée côté serveur. |

Chaque rôle (super administrateur, responsable d'usine, opérateur OT,
inspecteur qualité, auditeur sécurité, compte de service) ne voit, côté
serveur comme côté interface, que ce dont il a besoin. L'interface est
disponible en français et en anglais, suit la préférence système pour le
mode clair/sombre, et reste utilisable d'un téléphone à un grand écran.

## Architecture

Le système suit le **modèle de Purdue** : chaque service est rattaché à un
niveau de confiance, et le franchissement de la frontière OT → IT est
**impossible par construction**, pas seulement par configuration.

```
Niveau 0-1   Niveau 2-3        Niveau 3,5          Niveau 4         Niveau 5
┌─────────┐  ┌──────────────┐  ┌───────────────┐  ┌─────────────┐  ┌──────────────┐
│ Automate│─►│ Passerelle   │─►│ Diode de       │─►│ API +       │─►│ Console web  │
│ du four │  │ (lecture     │  │ données (UDP,  │  │ PostgreSQL  │  │ (React/TS)   │
│ (C,     │  │ seule,       │  │ sens unique,   │  │             │  │              │
│ Modbus) │  │ Modbus TCP)  │  │ signée Ed25519)│  │             │  │              │
└─────────┘  └──────────────┘  └───────────────┘  └─────────────┘  └──────────────┘
    OT                               DMZ                      IT
```

La diode de données est un **émetteur UDP sans aucune fonction de
réception** : il n'existe techniquement aucun chemin réseau pour qu'une
commande émise depuis le portail web atteigne l'automate. Cette propriété a
été vérifiée par une attaque réseau réelle, pas seulement documentée — voir
le [rapport technique](docs/reports/rapport_technique.pdf).

## Pile technologique

| Composant | Technologies |
| --- | --- |
| Automate (`services/ot-plc-daemon`) | C11, Modbus TCP, `poll()`, zéro allocation dynamique résiduelle |
| Passerelle (`services/ot-edge-gateway`) | Python 3.12, client Modbus lecture seule, signature Ed25519 |
| API (`services/backend-api`) | FastAPI, asyncpg, Pydantic v2, Argon2id, JWT (HS256), AES-256-GCM, scikit-learn |
| Console (`services/frontend-ui`) | React 18, TypeScript strict, Vite, Zustand, CSP stricte sans script inline |
| Base de données | PostgreSQL 16 + pgAudit, migrations Alembic |
| Infrastructure | Docker, Ansible (durcissement CIS), Terraform, GitHub Actions (7 étapes) |

## Démarrage rapide

### Prérequis

- Docker (ou Colima sur macOS)
- Python 3.12
- Node.js ≥ 20
- Un compilateur C11 (`cc`/`clang`)

### Lancer toute la chaîne

```bash
scripts/dev_up.sh
```

Ce script démarre PostgreSQL (avec pgAudit), génère les clés de la
passerelle, crée les comptes et les données de démonstration, compile et
lance l'automate, démarre la passerelle, la diode et l'API, puis la console
sur **http://localhost:5173**.

```bash
scripts/dev_down.sh
```

arrête proprement l'ensemble.

Les identifiants des comptes de démonstration sont écrits dans
`.dev-credentials.json` à la racine du dépôt (fichier ignoré par Git, généré
localement à chaque lancement).

## Comptes de démonstration

| Rôle | Accès |
| --- | --- |
| Super administrateur | Toute la console |
| Responsable d'usine | Production, stocks, commandes, clients, assistant |
| Opérateur OT | Production, stocks, assistant |
| Inspecteur qualité | Production uniquement |
| Auditeur sécurité | Sécurité, journal d'audit, clients |
| Compte de service (passerelle) | Aucun accès à la console |

Les mots de passe sont générés aléatoirement à chaque création des comptes
de démonstration (`scripts/dev_seed_users.py`) et ne sont jamais versionnés.

## Structure du dépôt

```
poc-glass/
  database/                 Schémas SQL et migrations Alembic
  docs/
    architecture/           Dossiers d'architecture (DAT, diode, LLM Guard, CSP)
    grc/                    Analyse de risques EBIOS RM
    specifications/         Spécifications techniques par étape
    reports/                Rapport de projet et rapport technique (PDF + sources LaTeX)
  infra/
    docker/                 PostgreSQL durci + docker-compose
    ansible/                Durcissement système (CIS Benchmarks)
    terraform/              Infrastructure déclarative
  redteam/                  Outils de test d'intrusion Modbus (encadrés, autorisation requise)
  scripts/                  Démarrage/arrêt local, données de démonstration
  security/                 Configuration du pipeline SAST/SCA
  services/
    backend-api/            API FastAPI (app/api, app/core, app/services)
    frontend-ui/             Console React/TypeScript
    ot-plc-daemon/           Automate C11 (simulateur + serveur Modbus)
    ot-edge-gateway/         Passerelle de collecte
    soc-siem/                Détection et corrélation
  tests/                    Tests d'intégration et de sécurité transverses
```

## Sécurité

- **Identité** : mots de passe en Argon2id (RFC 9106), jetons JWT révocables,
  verrouillage après plusieurs échecs.
- **Autorisation** : contrôle par rôle (RBAC) sur chaque route, complété par
  des règles contextuelles (ABAC) en échec fermé.
- **Confidentialité** : données personnelles des clients chiffrées au repos
  (AES-256-GCM).
- **Intégrité des mesures** : chaque trame de la passerelle est scellée
  (SHA-256 + Ed25519) et numérotée pour empêcher le rejeu.
- **Assistant IA** : quatre barrières successives (filtrage d'entrée,
  recherche cloisonnée, génération contrainte, contrôle de sortie physique).
- **Traçabilité** : journal d'audit chaîné et immuable (déclencheur SQL),
  y compris pour les tentatives refusées.

Le détail de chaque mécanisme, avec ses paramètres exacts, est dans le
[rapport technique](docs/reports/rapport_technique.pdf).

## Tests et qualité

| Domaine | Résultat |
| --- | --- |
| API et logique métier (pytest, PostgreSQL réel) | 563 tests passés |
| Interface web (Vitest) | 122 tests passés |
| Automate C — unitaires | 22 tests passés |
| Automate C — fuzzing | 763 cas, 0 crash, 0 fuite mémoire |
| Passerelle de collecte | 20 tests passés |
| Tests de sécurité (diode, LLM Guard, ML) | 133 tests passés |
| Typage statique strict (mypy) | 0 erreur |
| Analyse de sécurité statique (bandit) | 0 anomalie moyenne/haute |

L'intégration continue (GitHub Actions) exécute sept étapes à chaque
modification : lint, tests, analyse de sécurité statique, audit des
dépendances, construction des images Docker, inventaire logiciel (SBOM) et
signature des artefacts.

## Documentation complète

- [`docs/reports/rapport_projet.pdf`](docs/reports/rapport_projet.pdf) —
  présentation du projet, fonctionnalités illustrées, résultats.
- [`docs/reports/rapport_technique.pdf`](docs/reports/rapport_technique.pdf)
  — architecture, implémentation, sécurité, tests, déploiement.
- [`docs/architecture/`](docs/architecture) — dossiers d'architecture
  détaillés (diode de données, garde LLM, sécurité frontend).
- [`docs/grc/EBIOS_RM_SECURIGLASS.md`](docs/grc/EBIOS_RM_SECURIGLASS.md) —
  analyse de risques EBIOS RM.
- [`docs/specifications/`](docs/specifications) — spécifications techniques
  par étape de construction.

## Limites connues

Ce projet est une démonstration technique. Les éléments suivants sont
volontairement hors périmètre et ne doivent pas être lus comme implémentés :

- Détection réseau directe sur le segment OT (une attaque Modbus qui ne
  passe pas par l'application n'apparaît pas dans le flux d'alertes).
- Réplication à froid et plan de reprise d'activité.
- Signature applicative des consignes envoyées à l'automate.
- Image Docker *distroless* pour le backend.
- Aucune autorité d'homologation ne s'est prononcée sur ce système.

Le détail complet figure au chapitre « Limites connues et travaux futurs »
du rapport technique.
