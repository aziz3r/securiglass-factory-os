# Red Team Modbus/TCP — SecuriGlass Factory OS

> **Usage strictement réservé** aux tests d'intrusion autorisés sur le banc de
> démonstration SecuriGlass. Ces scripts ne doivent jamais être exécutés contre
> un automate, un réseau ou un système dont vous n'êtes pas le propriétaire ou
> pour lequel vous ne disposez pas d'une autorisation écrite et signée.

## 1. Périmètre autorisé (appliqué par le code)

| Élément | Valeur autorisée |
| :--- | :--- |
| Cible | `127.0.0.1/32` **ou** `10.10.30.0/24` (gateway / automates du labo) |
| Port | `5020` uniquement (simulateur d'automate SecuriGlass) |
| Débit | 0,1 à 20 opérations/seconde (défaut 5) |
| Opérations | 1 à 1000 par exécution (défaut 50 ; rejeu 10) |
| Écriture / rejeu | `--i-have-authorization` **obligatoire** |
| Résolution DNS | interdite : la cible doit être une IPv4 littérale |
| Journal | `redteam/logs/redteam-AAAAMMJJ.jsonl` (ou `--log-dir`) |

Le sous-réseau `10.10.20.0/24` (salle de contrôle) est **volontairement refusé
comme cible** : il représente la zone à compromettre dans le scénario, pas le
point d'émission. Le code refuse aussi les adresses publiques, link-local,
multicast, `0.0.0.0` et les noms d'hôtes.

## 2. Outils

| Script | Rôle | Autorisation requise |
| :--- | :--- | :--- |
| `modbus_recon.py` | Lecture FC1/FC2/FC3/FC4 (bobines, entrées, registres) | Non (lecture seule) |
| `modbus_write.py` | Écriture FC5/FC6/FC15/FC16 (bobine/registre unique ou multiple) | **Oui** |
| `modbus_replay.py` | Rejeu de trames Modbus/TCP extraites d'un pcap | **Oui** |

Caractéristiques communes :

* construction MBAP/PDU explicite et testable sans réseau (`redteam/modbus_proto.py`) ;
* transport TCP réel via `StreamSocket` Scapy (`--mode stream`, sans root) ou
  émission L3 brute (`--mode raw`, root requis) ;
* limiteur de débit à jetons, plafond d'opérations, journal JSON Lines ;
* mode `--dry-run` pour inspecter la trame **sans l'envoyer** (mais avec
  autorisation obligatoire pour toute écriture/rejeu).

## 3. Installation

```bash
# Depuis la racine du dépôt — ne pas toucher au venv du backend
python3.12 -m venv siem/.venv
siem/.venv/bin/pip install -r siem/requirements-tools.txt
```

Ou, si le venv existe déjà :

```bash
siem/.venv/bin/pip install scapy pytest pyyaml
```

## 4. Exemples

### Reconnaissance (lecture seule)

```bash
siem/.venv/bin/python redteam/modbus_recon.py \
  --target 10.10.30.10 --function 3 --start 0 --count 20
```

### Écriture d'un registre (FC6)

```bash
siem/.venv/bin/python redteam/modbus_write.py \
  --target 127.0.0.1 --function 6 --address 0 --value 1 \
  --i-have-authorization --authorization-ref "LAB-2026-001"
```

### Écriture multiple (FC16)

```bash
siem/.venv/bin/python redteam/modbus_write.py \
  --target 10.10.30.10 --function 16 --address 10 --values 700,701,702 \
  --i-have-authorization --authorization-ref "LAB-2026-001" --dry-run
```

### Rejeu d'un pcap

```bash
siem/.venv/bin/python redteam/modbus_replay.py \
  --target 127.0.0.1 --pcap capture.pcap --filter-function 6 \
  --limit 3 --i-have-authorization --authorization-ref "LAB-2026-001"
```

### Tests

```bash
siem/.venv/bin/python -m pytest redteam/tests -q
```

Les tests de paquets sont **explicitement ignorés** si Scapy n'est pas installé
(`pytest.importorskip`), conformément à la contrainte « skip explicite ».

## 5. Journalisation et preuve

Chaque exécution écrit un JSON Lines horodaté UTC contenant : outil, action,
cible, port, unit-id, débit, numéro d'opération, drapeau d'autorisation,
référence d'autorisation, résultat/erreur, PID et utilisateur. Ces journaux
peuvent contenir des adresses IP internes : ils sont ignorés par git et doivent
être conservés selon la procédure de preuve (hash SHA-256, coffre en lecture
seule) décrite dans `incidents/REGISTRE_INCIDENTS.md`.

## 6. Règles d'engagement (RoE) minimales

1. **Autorisation écrite** préalable, avec périmètre, fenêtre horaire et
   personne de contact. La référence est passée à `--authorization-ref`.
2. **Fenêtre de test** : hors production ou pendant un arrêt planifié, jamais
   pendant une campagne de trempe.
3. **Aucune donnée réelle** : ne pas extraire de données clients, ne pas
   modifier les recettes de trempe au-delà des registres de test.
4. **Arrêt immédiat** si un effet de bord est observé (`emergency_stop_tripped`,
   dérive thermique, arrêt convoyeur) : couper l'outil, alerter l'opérateur,
   consigner dans le registre.
5. **Pas de scan de plage**, pas d'exploitation de vulnérabilité, pas de
   persistance, pas d'effacement de journaux.
6. **Restitution** : rapport horodaté, journal JSONL, captures et
   recommandations ; suppression des artefacts offensifs après clôture.

## 7. Ce que ces outils ne font pas

* Pas de découverte réseau (pas de scan de plage, pas de ping sweep).
* Pas d'exploitation de CVE, pas de payload de malware.
* Pas de contournement d'authentification ni de persistance.
* Pas d'exfiltration de données.
* Pas de ciblage d'un automate réel hors du banc autorisé.

## 8. Références

* Modbus Application Protocol Specification V1.1b3.
* MITRE ATT&CK for ICS : T0836, T0831, T0886, T0840, T0885.
* IEC 62443-3-3 : SR 3.2, SR 5.1, SR 6.1.
* Registre d'incidents Blue Team : [`incidents/REGISTRE_INCIDENTS.md`](incidents/REGISTRE_INCIDENTS.md).
