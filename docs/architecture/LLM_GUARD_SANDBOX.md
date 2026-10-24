# 🛡️ Architecture & Spécifications - Sandbox LLM Guard & RAG Sécurisé

**Référentiels :** OWASP Top 10 for LLM Applications (2025), IEC 62443-3-3, NIST AI Risk Management Framework (AI RMF).  

---

## 1. Modèle de Menaces (Threat Model) pour l'IA en Milieu Industriel

Dans une usine de verre de sécurité, l'assistant RAG (Retrieval-Augmented Generation) aide les opérateurs et ingénieurs à consulter les fiches techniques, les normes (EN 12150) et les procédures d'incident.
Les vecteurs d'attaque ciblés sont :
1. **Prompt Injection Directe (LLM01) :** Tentative par un utilisateur de modifier les consignes système pour contourner les verrous de sécurité thermique.
2. **Indirect Prompt Injection (LLM01) :** Injection malveillante insérée dans une commande client, une spécification fournisseur ou une note de lot.
3. **Exfiltration d'Informations Sensibles / PII (LLM06) :** Tentative d'extraire les secrets cryptographiques, les données clients ou les recettes protégées.
4. **Génération de Consignes Dangereuses (Safety Hallucination) :** Proposition par le LLM d'une consigne de température hors limites ($> 750^\circ\text{C}$) ou d'une pression insuffisante provoquant une explosion dans le caisson de trempe.

---

## 2. Architecture de la Sandbox "LLM Guard" en 4 Barrières

```
   Requête Utilisateur (Opérateur / Ingénieur)
                     │
                     ▼
  ┌────────────────────────────────────────────────────────┐
  │ BARRIÈRE 1 : Pre-Input Scanner (Filtrage Entrant)      │
  │ - Détection de motifs d'injection de prompt            │
  │ - Nettoyage et anonymisation PII                       │
  │ - Blocage des mots-clés d'évasion système              │
  └────────────────────────────────────────────────────────┘
                     │ (Si Sain) ───► [Si Suspect : Rejet HTTP 400 + Alerte SOC]
                     ▼
  ┌────────────────────────────────────────────────────────┐
  │ BARRIÈRE 2 : Retrieval Cloisonné & Contexte Sanitisé   │
  │ - RAG contextuel strict : extraction des fiches EN12150│
  │ - Isolation des fragments documentaires                │
  └────────────────────────────────────────────────────────┘
                     │
                     ▼
  ┌────────────────────────────────────────────────────────┐
  │ BARRIÈRE 3 : Exécution en Sandbox Déterministe         │
  │ - Température bridée (0.0 à 0.2)                       │
  │ - Schéma de sortie JSON forcé (Pydantic constrained)   │
  │ - Timeout dur et sandbox d'exécution mémoire           │
  └────────────────────────────────────────────────────────┘
                     │
                     ▼
  ┌────────────────────────────────────────────────────────┐
  │ BARRIÈRE 4 : Post-Output Guard (Garantie de Sûreté)    │
  │ - Vérificateur des limites physiques EN 12150 :        │
  │   * T° four strictement bridée [600°C - 740°C]         │
  │   * Pression trempe [1.5 - 6.5 bar]                    │
  │ - Détection de fuite de prompt système                 │
  └────────────────────────────────────────────────────────┘
                     │
                     ▼
             Réponse Sécurisée
```

---

## 3. Spécifications du Détecteur d'Anomalies ML (Isolation Forest)

Le composant ML surveille en continu la télémétrie four reçue par la Data Diode pour détecter les dérives de capteurs, les pannes d'éléments chauffants et les chutes de pression avant accident :
* **Algorithme :** `IsolationForest` (paramètres : `n_estimators=100`, `contamination=0.03`, `random_state=42`).
* **Vecteur d'entrée (Features standardisées) :**
  1. `temp_zone1_c`
  2. `temp_zone2_c`
  3. `temp_zone3_c`
  4. `temp_zone4_c`
  5. `glass_pyrometer_temp_c`
  6. `quench_pressure_bar`
  7. `conveyor_speed_m_min`
  8. `blower_current_amps`
  9. `power_consumption_kw`
* **Sortie :** `is_anomaly: bool` (True si anomalie détectée), `anomaly_score: float` (score d'isolement $[-1.0, 1.0]$), `severity: str` (`NORMAL`, `WARNING`, `CRITICAL`).
