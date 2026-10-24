-- ============================================================================
-- SecuriGlass Factory OS - Étape 1 : Permissions SQL & Rôles PostgreSQL
-- Implémentation du Principe du Moindre Privilège (PoLP)
-- ============================================================================

-- 1. Création des rôles PostgreSQL (s'ils n'existent pas)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_super_admin') THEN
        CREATE ROLE role_super_admin NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_security_auditor') THEN
        CREATE ROLE role_security_auditor NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_plant_manager') THEN
        CREATE ROLE role_plant_manager NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_ot_operator') THEN
        CREATE ROLE role_ot_operator NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_quality_inspector') THEN
        CREATE ROLE role_quality_inspector NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_edge_service') THEN
        CREATE ROLE role_edge_service NOLOGIN;
    END IF;
END $$;

-- 2. Privilèges sur le Schéma sec_data
GRANT USAGE ON SCHEMA sec_data TO role_super_admin, role_security_auditor, role_plant_manager;

-- Super Admin : Contrôle sur les comptes, permissions et ABAC
GRANT SELECT, INSERT, UPDATE, DELETE ON sec_data.users TO role_super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON sec_data.user_roles TO role_super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON sec_data.roles TO role_super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON sec_data.role_permissions TO role_super_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON sec_data.abac_policies TO role_super_admin;
GRANT SELECT, INSERT ON sec_data.token_revocations TO role_super_admin;
GRANT SELECT, INSERT ON sec_data.audit_logs TO role_super_admin; -- STRICTEMENT PAS D'UPDATE/DELETE

-- Security Auditor : Lecture seule stricte sur tout sec_data
GRANT SELECT ON ALL TABLES IN SCHEMA sec_data TO role_security_auditor;

-- 3. Privilèges sur le Schéma it_data
GRANT USAGE ON SCHEMA it_data TO role_super_admin, role_security_auditor, role_plant_manager, role_ot_operator, role_quality_inspector;

-- Plant Manager : Gestion complète des commandes, recettes et lots
GRANT SELECT, INSERT, UPDATE ON it_data.customers TO role_plant_manager;
GRANT SELECT, INSERT, UPDATE ON it_data.recipes TO role_plant_manager;
GRANT SELECT, INSERT, UPDATE, DELETE ON it_data.glass_orders TO role_plant_manager;
GRANT SELECT, INSERT, UPDATE ON it_data.production_batches TO role_plant_manager;

-- Opérateur OT : Lecture recettes/commandes, mise à jour du statut des lots en cours
GRANT SELECT ON it_data.recipes TO role_ot_operator;
GRANT SELECT ON it_data.glass_orders TO role_ot_operator;
GRANT SELECT, UPDATE (status, started_at, finished_at) ON it_data.production_batches TO role_ot_operator;

-- Contrôleur Qualité : Mise à jour des rebuts et conformité
GRANT SELECT ON it_data.recipes TO role_quality_inspector;
GRANT SELECT ON it_data.glass_orders TO role_quality_inspector;
GRANT SELECT, UPDATE (scrapped_quantity, status) ON it_data.production_batches TO role_quality_inspector;

-- 4. Privilèges sur le Schéma ot_data
GRANT USAGE ON SCHEMA ot_data TO role_super_admin, role_security_auditor, role_plant_manager, role_ot_operator, role_quality_inspector, role_edge_service;

-- Edge Service (Data Diode) : Strictement INSERT SEUL (Aucun SELECT, UPDATE ou DELETE)
GRANT INSERT ON ot_data.furnace_telemetry TO role_edge_service;
GRANT INSERT ON ot_data.autoclave_telemetry TO role_edge_service;
GRANT INSERT ON ot_data.diode_import_log TO role_edge_service;
GRANT USAGE, SELECT ON SEQUENCE ot_data.furnace_telemetry_id_seq TO role_edge_service;
GRANT USAGE, SELECT ON SEQUENCE ot_data.autoclave_telemetry_id_seq TO role_edge_service;

-- Opérateur & Ingénieur Process : Lecture de la télémétrie
GRANT SELECT ON ot_data.production_lines TO role_plant_manager, role_ot_operator, role_quality_inspector, role_super_admin;
GRANT SELECT ON ot_data.plc_controllers TO role_plant_manager, role_ot_operator, role_super_admin;
GRANT SELECT ON ot_data.furnace_telemetry TO role_plant_manager, role_ot_operator, role_quality_inspector, role_security_auditor;
GRANT SELECT ON ot_data.autoclave_telemetry TO role_plant_manager, role_ot_operator, role_quality_inspector, role_security_auditor;
GRANT SELECT, INSERT, UPDATE ON ot_data.quality_defects TO role_quality_inspector;
GRANT SELECT ON ot_data.quality_defects TO role_plant_manager, role_ot_operator, role_super_admin;
