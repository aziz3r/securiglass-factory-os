-- ============================================================================
-- SecuriGlass Factory OS - Étape 1 : Schéma Sécurité & IAM sec_data
-- Modèle RBAC / ABAC, Authentification Argon2id et Audit Immuable
-- ============================================================================

-- 1. Table des Utilisateurs
CREATE TABLE IF NOT EXISTS sec_data.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, -- Format Argon2id : $argon2id$v=19$m=65536,t=3,p=4$...
    salt VARCHAR(64) NOT NULL,
    clearance_level SMALLINT NOT NULL DEFAULT 1 CHECK (clearance_level BETWEEN 1 AND 5),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret_encrypted BYTEA NULL,
    failed_login_attempts SMALLINT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON sec_data.users (username);
CREATE INDEX IF NOT EXISTS idx_users_email ON sec_data.users (email);

-- 2. Table des Rôles Standardisés
CREATE TABLE IF NOT EXISTS sec_data.roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_code VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(64) NOT NULL,
    description TEXT NULL,
    default_clearance SMALLINT NOT NULL DEFAULT 1 CHECK (default_clearance BETWEEN 1 AND 5),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Table des Permissions Fines
CREATE TABLE IF NOT EXISTS sec_data.permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    perm_code VARCHAR(64) NOT NULL UNIQUE,
    module VARCHAR(32) NOT NULL CHECK (module IN ('OT', 'IT', 'SEC', 'SOC')),
    description TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 4. Association Utilisateur <-> Rôles
CREATE TABLE IF NOT EXISTS sec_data.user_roles (
    user_id UUID NOT NULL REFERENCES sec_data.users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES sec_data.roles(id) ON DELETE RESTRICT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID NULL REFERENCES sec_data.users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

-- 5. Association Rôle <-> Permissions
CREATE TABLE IF NOT EXISTS sec_data.role_permissions (
    role_id UUID NOT NULL REFERENCES sec_data.roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES sec_data.permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- 6. Politiques Contextuelles ABAC (Attribute-Based Access Control)
CREATE TABLE IF NOT EXISTS sec_data.abac_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_name VARCHAR(64) NOT NULL UNIQUE,
    effect VARCHAR(8) NOT NULL CHECK (effect IN ('ALLOW', 'DENY')),
    subject_role VARCHAR(32) NOT NULL, -- Ex: 'OT_OPERATOR' ou '*'
    action_verb VARCHAR(32) NOT NULL,  -- Ex: 'WRITE', 'EXECUTE', 'APPROVE'
    resource_urn VARCHAR(128) NOT NULL,-- Ex: 'urn:securiglass:ot:furnace:*'
    rule_condition JSONB NOT NULL,     -- Expressions: ip_cidr, time_range, mtls_cert_issuer
    description TEXT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 7. Liste de Révocation des Jetons JWT (Token Revocations / JTI Blocklist)
CREATE TABLE IF NOT EXISTS sec_data.token_revocations (
    jti UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES sec_data.users(id) ON DELETE CASCADE,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    reason VARCHAR(128) NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON sec_data.token_revocations (expires_at);

-- 8. Piste d'Audit Immuable avec Chaînage Cryptographique (SHA-256)
CREATE TABLE IF NOT EXISTS sec_data.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(64) NOT NULL,
    actor_id UUID NULL, -- Instantané immuable de l'identité, SANS FK : une FK
                        -- ON DELETE SET NULL réécrirait la piste d'audit et
                        -- entrerait en conflit avec le trigger d'immuabilité (D10).
    actor_username VARCHAR(64) NOT NULL,
    actor_ip INET NOT NULL,
    client_cert_fingerprint VARCHAR(64) NULL,
    action VARCHAR(32) NOT NULL,
    resource VARCHAR(128) NOT NULL,
    outcome VARCHAR(16) NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),
    details JSONB NULL,
    prev_log_hash CHAR(64) NULL,
    current_hash CHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON sec_data.audit_logs (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON sec_data.audit_logs (actor_username);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event ON sec_data.audit_logs (event_type);

-- ============================================================================
-- VERROU D'IMMUABILITÉ DU JOURNAL D'AUDIT
-- ============================================================================
CREATE OR REPLACE FUNCTION sec_data.fn_prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'VIOLATION CRITIQUE DE SÉCURITÉ : Le journal d audit sec_data.audit_logs est strictement immuable (interdiction formelle de UPDATE / DELETE).';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON sec_data.audit_logs
    FOR EACH ROW EXECUTE FUNCTION sec_data.fn_prevent_audit_log_tampering();

-- ============================================================================
-- SEED INITIAL : RÔLES ET PERMISSIONS ESSENTIELLES
-- ============================================================================
INSERT INTO sec_data.roles (role_code, name, description, default_clearance) VALUES
    ('SUPER_ADMIN', 'Super Administrateur Système', 'Administration globale de la plateforme, gestion des comptes et secrets', 5),
    ('SECURITY_AUDITOR', 'Auditeur de Sécurité / GRC', 'Contrôle de conformité et consultation immuable des journaux d audit', 4),
    ('PLANT_MANAGER', 'Directeur d Usine / Production', 'Supervision des lignes de production et validation des recettes de trempe', 3),
    ('OT_OPERATOR', 'Opérateur Ligne de Trempe (OT)', 'Pilotage de la ligne de trempe et supervision télémétrique directe', 2),
    ('QUALITY_INSPECTOR', 'Contrôleur Qualité Verre Sécurit', 'Inspection optique, qualification matière et enregistrement des non-conformités', 2),
    ('SERVICE_ACCOUNT_EDGE', 'Passerelle Edge / Data Diode', 'Compte de service automate pour l ingestion de télémétrie certifiée', 2)
ON CONFLICT (role_code) DO NOTHING;

INSERT INTO sec_data.permissions (perm_code, module, description) VALUES
    ('sec:users:manage', 'SEC', 'Création, modification et désactivation des comptes utilisateurs'),
    ('sec:audit:read', 'SEC', 'Lecture et vérification du journal d audit cryptographique'),
    ('sec:abac:configure', 'SEC', 'Modification des règles contextuelles ABAC'),
    ('it:orders:read', 'IT', 'Consultation des commandes clients et du carnet de commandes'),
    ('it:orders:write', 'IT', 'Création et mise à jour des commandes clients'),
    ('it:recipes:manage', 'IT', 'Édition et soumission des recettes thermiques de trempe'),
    ('it:recipes:approve', 'IT', 'Validation métrologique et approbation des recettes thermiques'),
    ('it:batches:schedule', 'IT', 'Planification et ordonnancement des lots de fabrication'),
    ('ot:telemetry:read', 'OT', 'Visualisation en direct et historique de la télémétrie four et autoclave'),
    ('ot:telemetry:insert', 'OT', 'Injection unidirectionnelle de mesures télémétriques certifiées'),
    ('ot:quality:record', 'OT', 'Enregistrement de défauts détectés par scanner optique'),
    ('ot:control:write', 'OT', 'Envoi de consignes de fonctionnement aux automates industriels')
ON CONFLICT (perm_code) DO NOTHING;
