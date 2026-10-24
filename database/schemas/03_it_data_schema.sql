-- ============================================================================
-- SecuriGlass Factory OS - Étape 1 : Schéma Métier it_data (Niveau 4)
-- Données de Production, Recettes de Trempe & Clients RGPD (TDE Ready)
-- ============================================================================

-- 1. Table des Clients B2B (Données Personnelles Chiffrées au Repos)
CREATE TABLE IF NOT EXISTS it_data.customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_name VARCHAR(128) NOT NULL,
    -- Données personnelles soumises au RGPD : Chiffrement TDE / AES-256-GCM
    contact_name_encrypted BYTEA NOT NULL,
    email_encrypted BYTEA NOT NULL,
    phone_encrypted BYTEA NULL,
    vat_number VARCHAR(32) NULL,
    country_code CHAR(2) NOT NULL DEFAULT 'FR',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_customers_company ON it_data.customers (company_name);

-- 2. Table des Recettes Thermiques et Procédés Industriels
CREATE TABLE IF NOT EXISTS it_data.recipes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipe_code VARCHAR(32) NOT NULL UNIQUE,
    name VARCHAR(96) NOT NULL,
    glass_type VARCHAR(32) NOT NULL CHECK (glass_type IN (
        'FLOAT_TEMPERED',
        'LAMINATED_SECURITY',
        'LAMINATED_ACOUSTIC',
        'BULLETPROOF_BR4',
        'SOLAR_CONTROL_TEMPERED'
    )),
    thickness_nominal_mm NUMERIC(4,1) NOT NULL CHECK (thickness_nominal_mm > 0.0),
    target_furnace_temp_c NUMERIC(5,1) NOT NULL CHECK (target_furnace_temp_c BETWEEN 600.0 AND 750.0),
    target_quench_pressure_bar NUMERIC(4,2) NOT NULL CHECK (target_quench_pressure_bar BETWEEN 0.50 AND 10.00),
    heating_duration_s INTEGER NOT NULL CHECK (heating_duration_s > 0),
    cooling_duration_s INTEGER NOT NULL CHECK (cooling_duration_s > 0),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    is_approved BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by UUID NULL, -- Référence sec_data.users(id)
    approved_at TIMESTAMPTZ NULL,
    created_by UUID NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_recipes_code ON it_data.recipes (recipe_code);

-- 3. Table des Commandes de Vitrages Sécurisés
CREATE TABLE IF NOT EXISTS it_data.glass_orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_ref VARCHAR(32) NOT NULL UNIQUE,
    customer_id UUID NOT NULL REFERENCES it_data.customers(id) ON DELETE RESTRICT,
    recipe_id UUID NOT NULL REFERENCES it_data.recipes(id) ON DELETE RESTRICT,
    width_mm NUMERIC(6,1) NOT NULL CHECK (width_mm >= 100.0 AND width_mm <= 6000.0),
    height_mm NUMERIC(6,1) NOT NULL CHECK (height_mm >= 100.0 AND height_mm <= 3300.0),
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    status VARCHAR(24) NOT NULL DEFAULT 'SUBMITTED' CHECK (status IN (
        'DRAFT',
        'SUBMITTED',
        'PLANNED',
        'IN_PRODUCTION',
        'QUALITY_CHECK',
        'READY_DISPATCH',
        'DELIVERED',
        'CANCELLED'
    )),
    target_delivery_date DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_orders_ref ON it_data.glass_orders (order_ref);
CREATE INDEX IF NOT EXISTS idx_orders_customer ON it_data.glass_orders (customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_status ON it_data.glass_orders (status);

-- 4. Table des Lots de Fabrication (Ordonnancement Usine)
CREATE TABLE IF NOT EXISTS it_data.production_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_code VARCHAR(32) NOT NULL UNIQUE,
    order_id UUID NOT NULL REFERENCES it_data.glass_orders(id) ON DELETE RESTRICT,
    line_code VARCHAR(32) NOT NULL,
    planned_quantity INTEGER NOT NULL CHECK (planned_quantity > 0),
    produced_quantity INTEGER NOT NULL DEFAULT 0 CHECK (produced_quantity >= 0),
    scrapped_quantity INTEGER NOT NULL DEFAULT 0 CHECK (scrapped_quantity >= 0),
    status VARCHAR(24) NOT NULL DEFAULT 'PLANNED' CHECK (status IN (
        'PLANNED',
        'IN_PROGRESS',
        'QUALITY_HOLD',
        'COMPLETED',
        'ABORTED'
    )),
    started_at TIMESTAMPTZ NULL,
    finished_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_batches_code ON it_data.production_batches (batch_code);
CREATE INDEX IF NOT EXISTS idx_batches_order ON it_data.production_batches (order_id);
CREATE INDEX IF NOT EXISTS idx_batches_status ON it_data.production_batches (status);
