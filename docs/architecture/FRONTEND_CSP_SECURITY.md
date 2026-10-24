# 🛡️ Architecture & Spécifications - Frontend React & "Client-Side Security" (Étape 4)

**Référentiels :** OWASP ASVS v4.0 (V14 - Front-End Security), CSP Level 3 (W3C), NIST SP 800-63B.  

---

## 1. Politique de Sécurité du Contenu (Strict CSP Level 3)

Le frontend SecuriGlass applique une politique de restriction absolue interdisant tout chargement de ressource non signée ou externe (`default-src 'none'`) :

```http
Content-Security-Policy: 
    default-src 'none';
    script-src 'self';
    style-src 'self' 'unsafe-inline';
    img-src 'self' data:;
    connect-src 'self' ws: wss: http://localhost:8000;
    font-src 'self';
    object-src 'none';
    base-uri 'none';
    frame-ancestors 'none';
    form-action 'self';
    upgrade-insecure-requests;
```

### Règles d'Inviolabilité Client :
1. **Zéro `localStorage` pour les Secrets :** Le jeton d'accès JWT (`access_token`) est conservé **strictement en mémoire volatile** (closure ou store Zustand mémoire). Aucun stockage persistant dans `localStorage` ou `sessionStorage` pour empêcher toute exfiltration en cas de faille XSS.
2. **Cloisonnement des Stores Zustand :**
   - `useAuthStore` : Identité, rôle (`role_code`), niveau d'habilitation (`clearance_level`), jeton en mémoire.
   - `useTelemetryStore` : Télémétrie temps réel des 4 zones du four reçue par WebSocket sécurisé (WSS), tampon circulaire glissant limité à 200 points (prévention des fuites mémoire navigateur).
   - `useProductionStore` : Commandes de vitrages et lots de trempe.
   - `useSecurityStore` : Journaux d'audit et alertes SIEM.
3. **Protection XSS Stricte :** Interdiction absolue de `dangerouslySetInnerHTML`. Tous les affichages dynamiques sont échappés par React.

---

## 2. Interface Utilisateur Industrielle (React SPA)

L'IHM supervise l'usine de verre sécurit avec 4 vues spécialisées par rôle RBAC :
1. **Cockpit Ligne de Trempe (Opérateur OT / Plant Manager) :**
   - Visualisation temps réel des températures des 4 zones (650°C-720°C) avec alertes visuelles de surchauffe.
   - Jauge de pression de trempe (bar) et tachymètre rouleaux (m/min).
   - Indicateur d'état du cycle (IDLE, HEATING, QUENCHING, E-STOP) et bouton d'Arrêt d'Urgence.
2. **Contrôle Qualité & Détection Défauts (Quality Inspector) :**
   - Liste des anomalies détectées par le modèle ML Isolation Forest (signatures de panne en rouge).
   - Scanner optique de contraintes de surface.
3. **Assistant RAG Sécurisé (LLM Guard Interface) :**
   - Consultation des fiches techniques EN 12150.
   - Affichage des garanties de sécurité et des sources normatives.
4. **Console d'Audit & Sécurité (Security Auditor / Super Admin) :**
   - Journal d'audit avec vérification visuelle de l'intégrité de la chaîne cryptographique SHA-256.

---

## 3. WebSocket Sécurisé (WSS Streaming)

* Endpoint backend FastAPI : `/api/v1/ws/telemetry`
* Authentification : Le client transmet le jeton Bearer JWT au handshake (`?token=...` ou subprotocol).
* Streaming régulé : Émission de paquets télémétriques toutes les 500 ms vers les postes autorisés.
