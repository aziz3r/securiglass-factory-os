-- ============================================================================
-- SecuriGlass Factory OS - Extension : stocks de matières premières (Niveau 4)
-- Alimente les jauges de la console et est décrémenté à chaque commande client.
-- ============================================================================

CREATE TABLE IF NOT EXISTS it_data.raw_materials (
    material_code VARCHAR(32) PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    unit VARCHAR(8) NOT NULL,
    stock_qty NUMERIC(12,2) NOT NULL CHECK (stock_qty >= 0),
    capacity_qty NUMERIC(12,2) NOT NULL CHECK (capacity_qty > 0),
    reorder_level NUMERIC(12,2) NOT NULL CHECK (reorder_level >= 0),
    -- consommation par m² de verre fini et par mm d'épaisseur
    consumption_per_m2_mm NUMERIC(8,4) NOT NULL CHECK (consumption_per_m2_mm >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (stock_qty <= capacity_qty)
);

INSERT INTO it_data.raw_materials
    (material_code, name, unit, stock_qty, capacity_qty, reorder_level, consumption_per_m2_mm)
VALUES
    ('SAND',      'Sable siliceux',     'kg', 42000, 60000, 12000, 1.2000),
    ('SODA',      'Carbonate de sodium','kg', 13500, 20000,  4000, 0.4000),
    ('LIMESTONE', 'Calcaire',           'kg',  9800, 15000,  3000, 0.3000),
    ('CULLET',    'Calcin recyclé',     'kg', 21000, 30000,  6000, 0.5000),
    ('COATING',   'Revêtement bas-émissif', 'L',  620,  1000,   200, 0.0020),
    ('PALLETS',   'Palettes bois',      'u',    180,   300,    60, 0.0020)
ON CONFLICT (material_code) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'role_plant_manager') THEN
        GRANT SELECT, UPDATE ON it_data.raw_materials TO role_plant_manager;
        GRANT SELECT ON it_data.raw_materials TO role_ot_operator, role_quality_inspector,
            role_super_admin, role_security_auditor;
    END IF;
END $$;
