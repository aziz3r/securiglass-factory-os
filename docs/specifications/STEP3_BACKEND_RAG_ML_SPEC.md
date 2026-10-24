# 🧠 Spécification Technique - Étape 3 : Microservices Backend, RAG & ML

**Normes cibles :** OWASP Top 10 for LLM (2025), IEC 62443-3-3, EN 12150.

---

## 1. Périmètre Fonctionnel de l'Étape 3
1. **Limiteur de Débit (Rate Limiting) :** Protection contre les attaques DoS et le bruteforce applicatif (Token Bucket avec fallback mémoire résilient).
2. **Détection d'Anomalies ML Procédé (Isolation Forest) :** Modèle non-supervisé entraîné sur la télémétrie four pour identifier en temps réel les dérives thermiques et pannes de soufflage.
3. **Sandbox LLM Guard & RAG Sécurisé :** Assistant technique industriel opérant en environnement hermétique avec détection d'injection de prompt, bridage des sorties et contrôle physique des recettes générées.

---

## 2. Directives d'implémentation (Backend)

### A. Rate Limiting Middleware (`app/core/rate_limiter.py`)
* Implémenter un middleware / dépendance FastAPI de Rate Limiting basé sur l'algorithme Token Bucket :
  * `/api/v1/auth/login` : 5 requêtes par minute par IP.
  * `/api/v1/rag/query` : 10 requêtes par minute par utilisateur.
  * API générale : 60 requêtes par minute par IP.
* En cas de dépassement : retourner HTTP 429 Too Many Requests avec les en-têtes standard `Retry-After`, `X-RateLimit-Limit`, `X-RateLimit-Remaining`.
* Résilience : Stockage mémoire thread-safe avec possibilité de persistance Redis.

### B. Moteur ML d'Anomalie Four (`app/services/ml_anomaly.py`)
* Implémenter la classe `FurnaceAnomalyDetector` :
  * Utilise `scikit-learn` `IsolationForest` avec un fallback pur Python / NumPy si scikit-learn n'est pas installé.
  * Entraînement sur les 9 features de télémétrie process (Zone 1-4, Pyromètre, Pression trempe, Vitesse rouleaux, Courant, Puissance).
  * Méthode `predict(sample: dict[str, float]) -> AnomalyResult` retournant `is_anomaly`, `anomaly_score` et `severity`.
  * Détection spécifique des signatures de panne usine :
    - Défaillance élément chauffant (une zone chute de $> 50^\circ\text{C}$ alors que la puissance augmente).
    - Perte de pression caisson de trempe ($< 1.8\text{ bar}$).
    - Blocage convoyeur rouleaux ($< 0.5\text{ m/min}$).
* Endpoints FastAPI (`app/api/ml.py`) :
  - `POST /api/v1/ml/predict` : Diagnostic temps réel d'un échantillon télémétrique.
  - `POST /api/v1/ml/train` : Entraînement / mise à jour du modèle sur un lot d'apprentissage.

### C. LLM Guard & RAG Sécurisé (`app/services/llm_guard.py` & `app/api/rag.py`)
* Implémenter `LLMGuardService` avec les 4 barrières de sécurité :
  1. **Pre-Input Scanner :**
     * Analyse sémantique et lexicale détectant les injections directes (`ignore previous instructions`, `override safety`, `dan mode`, `exfiltrate`, `system prompt`, balises `<script>`, `DROP TABLE`).
     * Lève `PromptInjectionDetected` (rejet immédiat HTTP 400 + log d'audit de sécurité).
  2. **Base de Connaissances RAG Locale (Knowledge Base) :**
     * Corpus technique intégrant les règles de trempe thermique EN 12150 (épaisseurs 4mm à 19mm, plages de chauffe nominales $650^\circ\text{C} - 710^\circ\text{C}$, pressions de trempe recommandées).
  3. **Générateur Contraint :**
     * Moteur déterministe respectant strictement le contexte fourni.
  4. **Post-Output Recipe Guard :**
     * Analyse la réponse générée : si une recette thermique ou des valeurs de température/pression sont suggérées, le garde valide qu'elles respectent rigoureusement les bornes de sécurité physiques :
       - Température four : entre $620^\circ\text{C}$ et $730^\circ\text{C}$.
       - Pression de trempe : entre $1.5\text{ bar}$ et $6.5\text{ bar}$.
       - Si hors bornes : rejet et remplacement par un message de sécurité.
* Endpoint FastAPI (`app/api/rag.py`) :
  - `POST /api/v1/rag/query` : Réservé aux rôles `OT_OPERATOR`, `PLANT_MANAGER`, `SUPER_ADMIN`.

---

## 3. Directives pour la phase de validation
1. **Tests Adversariaux Red Team RAG :** Fuzzing de prompts, attaques de jailbreak (DAN, Grand-mother exploit, prompt leak), injections indirectes.
2. **Validation des Scores ML :** Mesure de la matrice de confusion, précision, rappel et F1-score sur jeu de test étiqueté (anomalies réelles injectées).
3. **Stress Test Rate Limiter :** Validation du blocage effectif HTTP 429 sous rafale de requêtes concurrentes.
4. **Maintien de la Porte Qualité :** Couverture de test $> 85\%$, Bandit 0 faille, mypy strict 0 erreur.
