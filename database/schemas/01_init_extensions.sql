-- ============================================================================
-- SecuriGlass Factory OS - Étape 1 : Initialisation des Extensions & Schémas
-- Conformité : IEC 62443 / ISA-95 (Purdue) / OWASP ASVS v4.0
-- ============================================================================

-- 1. Activation des extensions cryptographiques et système
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Note : pgAudit requiert d'être listé dans shared_preload_libraries de postgresql.conf
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS "pgaudit";
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Extension pgaudit non chargée au niveau preload. Sera activée via configuration serveur.';
END $$;

-- 2. Création des schémas segmentés selon le modèle de Purdue
-- Schéma Sécurité, IAM et Piste d'Audit Immuable
CREATE SCHEMA IF NOT EXISTS sec_data;

-- Schéma Gestion Industrielle, Commandes Métier et Recettes (IT - Niveau 4)
CREATE SCHEMA IF NOT EXISTS it_data;

-- Schéma Télémétrie Lignes, Automates et Contrôle Procédé (OT - Niveaux 1-3)
CREATE SCHEMA IF NOT EXISTS ot_data;

-- 3. Révocation des privilèges par défaut sur le schéma public (Hardening CIS Benchmark)
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

COMMENT ON SCHEMA sec_data IS 'Périmètre Sécurité, Gestion des Identités, Politiques ABAC et Journal d Audit';
COMMENT ON SCHEMA it_data IS 'Périmètre Métier IT (Niveau 4) - Commandes clients, recettes de trempe, ordonnancement';
COMMENT ON SCHEMA ot_data IS 'Périmètre Opérationnel OT (Niveaux 1-3) - Lignes de trempe, télémétrie process et défauts';
