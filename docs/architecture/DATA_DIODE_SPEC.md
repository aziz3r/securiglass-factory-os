# 🛡️ Spécification Technique de la Data Diode Logique Unidirectionnelle

**Référentiel :** IEC 62443-3-3 (Zonage & Conduits de Sécurité) / Modèle de Purdue (iDMZ Niveau 3.5)  

---

## 1. Principe Fondamental du Flux Unidirectionnel (Simplex)

Une **Data Diode** (diode de données) est un dispositif réseau garantissant physiquement ou logiquement qu'aucun flux d'information ne peut transiter du réseau à plus faible niveau de sécurité (Niveau 4 IT / Niveau 5 SOC) vers le réseau de sûreté critique (Niveaux 0-3 OT).

```
[ Niveau 3 - OT LAN ]                                 [ Niveau 4 - IT LAN ]
  Gateway Edge OT                                       Diode Ingest Service
  (Diode Emitter TX)                                    (Diode Receiver RX)
         │                                                       │
         ▼                                                       ▼
 ┌───────────────┐        Flux Simplex Unidirectionnel     ┌───────────────┐
 │ Émetteur TX   │ ──────────────────────────────────────► │ Récepteur RX  │
 │ (Signataire)  │          (AUCUN ACK ENVOYÉ EN RETOUR)   │ (Vérificateur)│
 └───────────────┘                                         └───────────────┘
         │                                                       │
         │ UDP Datagram / Raw Stream                             │ Ingestion
         │ Pas de Socket TCP Bidirectionnelle                    ▼
         ▼                                                 ┌───────────────┐
  [ Isolation Totale ]                                     │ ot_data DB    │
                                                           └───────────────┘
```

### Règle d'or : "Zéro Retour / No Backchannel"
* Le récepteur IT RX n'ouvre **aucun canal émetteur** vers la zone OT.
* L'émetteur OT TX émet en mode **UDP Datagram aveugle** (Simplex). L'acquittement (ACK) réseau est proscrit pour éliminer tout risque de pivot ou de canal de contrôle C2 (Command & Control) vers les automates.
* La fiabilité d'acheminement est assurée par :
  1. Redondance d'envoi configurable (émission double ou FEC).
  2. Compteur de séquence monotone (`sequence_number`) pour détecter les pertes.
  3. Journalisation de conformité dans `ot_data.diode_import_log`.

---

## 2. Structure de Trame Binaire / Format de Paquet Diode

Chaque datagramme de la diode logique respecte le format d'encapsulation suivant :

```
+-------------------------------------------------------------------------------+
|                      EN-TÊTE FIXE DU DATAGRAMME (64 octets)                   |
+-------------------------------------------------------------------------------+
| Magique (4 o) : 0x53474444 ("SGDD" = SecuriGlass Data Diode)                  |
| Version Protocole (2 o) : 0x0002 (v2.0)                                       |
| Type de Message (2 o)   : 0x0001 (FURNACE_TELEMETRY), 0x0002 (AUTOCLAVE)      |
| Numéro de Séquence (8 o): uint64 monotone croissant                           |
| Horodatage UTC (8 o)   : uint64 epoch microsecondes                           |
| ID Émetteur (16 o)     : UUIDv4 de l'Edge Gateway OT                          |
| Longueur Payload (4 o) : uint32 (nombre d'octets du payload compressé/JSON)   |
| Réservé / Padding (20 o): 0x00                                                |
+-------------------------------------------------------------------------------+
|                       CORPS DE TÉLÉMÉTRIE (Variable)                          |
+-------------------------------------------------------------------------------+
| Payload JSON ou Protobuf contenant les enregistrements process                |
+-------------------------------------------------------------------------------+
|                       SEAU CRYPTOGRAPHIQUE (96 octets)                        |
+-------------------------------------------------------------------------------+
| Hash SHA-256 Payload (32 octets) : SHA256(Header[0..43] + Payload)           |
| Signature Ed25519 (64 octets)    : Ed25519_Sign(PrivKey_OT, Hash_SHA256)      |
+-------------------------------------------------------------------------------+
```

---

## 3. Sécurité Cryptographique & Anti-Rejeu
1. **Signature Ed25519 (RFC 8032) :** L'Edge Gateway possède une clé privée Ed25519 protégée. Le récepteur IT détient la clé publique correspondante. Toute trame altérée ou issue d'un attaquant est rejetée immédiatement.
2. **Anti-Rejeu (Replay Protection) :** Le récepteur RX maintient une fenêtre glissante de numéros de séquence (`last_seen_seq`). Tout paquet ayant un numéro $\le$ `last_seen_seq` ou un timestamp divergeant de plus de 30 secondes est consigné comme anomalie et rejeté.
3. **Conformité pgAudit / Immuabilité :** Chaque lot validé est consigné dans `ot_data.diode_import_log` avec son `packet_sha256` et sa signature.
