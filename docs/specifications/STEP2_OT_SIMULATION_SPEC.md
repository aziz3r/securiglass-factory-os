# 🏭 Spécification Technique - Étape 2 : Simulation OT & Protocoles Industriels

**Normes cibles :** IEC 62443-3-3, POSIX C11, Modbus Application Protocol V1.1b3.

---

## 1. Modélisation Physique du Four de Trempe (Securit Glass Furnace)

Le four de trempe thermique applique un gradient thermique violent sur le verre silico-sodo-calcique pour créer les contraintes de compression de surface caractéristiques du verre de sécurité (norme EN 12150) :
1. **Échauffement thermique :** 4 zones régulées jusqu'à $680^\circ\text{C} - 720^\circ\text{C}$ avec inertie thermique modélisée :
   $$\frac{dT}{dt} = \alpha \cdot (T_{\text{consigne}} - T) - \beta \cdot (T - T_{\text{ambiante}})$$
2. **Soufflage de trempe (Quench) :** Injection d'air froid comprimé (2.0 à 6.5 bars) via des caissons de soufflage supérieur et inférieur.
3. **Cas de rupture / Casse thermique :** Si le verre subit le soufflage alors que sa température de surface $T_{\text{verre}} < 620^\circ\text{C}$, ou si le convoyeur s'arrête en zone de chauffe, un événement de casse mécanique est levé (`THERMAL_SHOCK_BREAKAGE`).

---

## 2. Table d'Adressage Modbus TCP (Register Map)

Port d'écoute standard : **5020** (évite les privilèges root) ou configurable.

### Registres d'Entrée Analogiques (Input Registers - 3X / Fonction Modbus 0x04)
| Adresse | Registre | Unité / Échelle | Description |
| :---: | :---: | :---: | :--- |
| `30001` | `0x0000` | $0.1^\circ\text{C}$ (ex: $6850 = 685.0^\circ\text{C}$) | Température Zone 1 d'enfournement |
| `30002` | `0x0001` | $0.1^\circ\text{C}$ | Température Zone 2 centrale |
| `30003` | `0x0002` | $0.1^\circ\text{C}$ | Température Zone 3 centrale |
| `30004` | `0x0003` | $0.1^\circ\text{C}$ | Température Zone 4 sortie |
| `30005` | `0x0004` | $0.1^\circ\text{C}$ | Pyromètre optique température verre |
| `30006` | `0x0005` | $\text{mbar}$ (ex: $3500 = 3.50\text{ bar}$) | Pression d'air du caisson de trempe |
| `30007` | `0x0006` | $\text{cm/min}$ (ex: $450 = 4.50\text{ m/min}$) | Vitesse des rouleaux céramiques |
| `30008` | `0x0007` | $\text{RPM}$ | Vitesse de rotation des soufflantes |
| `30009` | `0x0008` | $0.1\text{ kW}$ | Puissance électrique instantanée |
| `30010` | `0x0009` | Bitfield | Drapeaux d'état process (Bit 0: Chauffe ON, Bit 1: Trempe ON, Bit 2: E-STOP, Bit 3: Rupture verre) |
| `30011` | `0x000A` | Énumération | État cycle : `0: IDLE, 1: PREHEAT, 2: HEATING, 3: QUENCHING, 4: COOLING, 5: E_STOP` |
| `30012` | `0x000B` | Code erreur | Code anomalie automate (0 = nominal) |

### Registres de Consigne (Holding Registers - 4X / Fonctions Modbus 0x03 & 0x06 / 0x10)
| Adresse | Registre | Unité / Échelle | Description |
| :---: | :---: | :---: | :--- |
| `40001` | `0x0000` | $0.1^\circ\text{C}$ (Plage: $5000 - 7500$) | Consigne Température Zone 1 |
| `40002` | `0x0001` | $0.1^\circ\text{C}$ | Consigne Température Zone 2 |
| `40003` | `0x0002` | $0.1^\circ\text{C}$ | Consigne Température Zone 3 |
| `40004` | `0x0003` | $0.1^\circ\text{C}$ | Consigne Température Zone 4 |
| `40005` | `0x0004` | $\text{mbar}$ (Plage: $500 - 8000$) | Consigne Pression de Trempe |
| `40006` | `0x0005` | $\text{cm/min}$ (Plage: $100 - 2500$) | Consigne Vitesse Convoyeur |
| `40007` | `0x0006` | Code commande | Ordre procédé : `1: START_CYCLE, 2: PAUSE, 3: RESUME, 4: E_STOP, 5: RESET` |

### Entrées Tout-Ou-Rien (Discrete Inputs - 1X / Fonction 0x02)
| Adresse | Bit | Description |
| :---: | :---: | :--- |
| `10001` | `0` | Bouton Arrêt d'Urgence Physique (0 = Déclenché / NF de sécurité) |
| `10002` | `1` | Verrouillage Sas d'Entrée Four (1 = Fermé) |
| `10003` | `2` | Pression Réseau Pneumatique OK (1 = Suffisante) |
| `10004` | `3` | Détecteur Présence Volume de Verre à l'Enfournement (1 = Détecté) |

---

## 3. Directives techniques d'implémentation

### A. Démon C de Simulation d'Automate (`services/ot-plc-daemon/`)
1. **Langage & Standards :** C11 standard (`-std=c11`), conforme POSIX (`-D_POSIX_C_SOURCE=200809L`).
2. **Gestion Mémoire Stricte :**
   - Aucune allocation dynamique non libérée.
   - 0 fuite mémoire certifiée sous Valgrind (`--leak-check=full --show-leak-kinds=all --error-exitcode=1`).
   - Prévention des débordements de tampon (`snprintf`, bornage explicite des tableaux).
3. **Moteur Modbus TCP :** Implémentation d'un serveur Modbus TCP non-bloquant ou multi-threadé (POSIX pthreads) traitant les trames standard MBAP (Transaction ID, Protocol ID = 0, Length, Unit ID = 1, Function Code, Data).
4. **Boucle Physique Temps Réel :** Timer POSIX ou `nanosleep` cadencé à 100ms mettant à jour les variables thermiques, la cinématique du verre et les alarmes.

### B. Gateway Edge OT Python (`services/ot-edge-gateway/`)
1. **Lecteur Modbus TCP :** Client asynchrone (`asyncio`) interrogeant périodiquement les registres 30001 à 30012.
2. **Validation des Trames :** Vérification de cohérence physique (rejet des températures négatives ou $>850^\circ\text{C}$).
3. **Émetteur Data Diode (TX) :**
   - Encapsulation des données selon [`DATA_DIODE_SPEC.md`](../architecture/DATA_DIODE_SPEC.md).
   - Signature Ed25519 du paquet télémétrique avec hachage SHA-256.
   - Envoi UDP simplex non-bloquant vers le port récepteur de l'iDMZ.

### C. Récepteur Data Diode IT (`services/backend-api/app/services/diode_receiver.py` ou standalone)
1. Écoute UDP simplex sur le réseau iDMZ.
2. Vérification cryptographique immédiate de la signature Ed25519 et du checksum SHA-256.
3. Vérification anti-rejeu du numéro de séquence.
4. Ingestion dans `ot_data.furnace_telemetry` et journalisation dans `ot_data.diode_import_log`.

---

## 4. Directives techniques de validation (DevSecOps & Red Team)
1. **Analyse Valgrind :** Exécution automatisée en boucle pour garantir 0 fuite mémoire, 0 invalid read/write sur le Démon C.
2. **Stress Test & Fuzzing Modbus :** Envoi de paquets Modbus corrompus, de dépassements de registres et de requêtes illégitimes pour éprouver la robustesse du Démon C.
3. **Tests Diode Unidirectionnelle :**
   - Vérification de l'absence totale de canal retour (tentative d'émission d'IT vers OT $\rightarrow$ blocage).
   - Test de résistance aux paquets rejoués ou à signature Ed25519 contrefaite.
4. **Documentation Doxygen :** Génération automatique de la documentation technique du code C.
