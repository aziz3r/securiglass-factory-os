-- ============================================================================
-- SecuriGlass Factory OS - Étape 1 : Schéma Opérationnel ot_data (Niveaux 1-3)
-- ============================================================================

-- 1. Table des Lignes de Production (Four de trempe, Lignes de feuilletage)
CREATE TABLE IF NOT EXISTS ot_data.production_lines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    line_code VARCHAR(32) NOT NULL UNIQUE,
    line_name VARCHAR(64) NOT NULL,
    purdue_level SMALLINT NOT NULL DEFAULT 2 CHECK (purdue_level BETWEEN 1 AND 3),
    ip_gateway INET NOT NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'OFFLINE' CHECK (status IN ('OFFLINE', 'RUNNING', 'MAINTENANCE', 'EMERGENCY_STOP')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Table des Automates Programmables (PLC / Démon C)
CREATE TABLE IF NOT EXISTS ot_data.plc_controllers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    line_id UUID NOT NULL REFERENCES ot_data.production_lines(id) ON DELETE RESTRICT,
    controller_tag VARCHAR(32) NOT NULL UNIQUE,
    model VARCHAR(64) NOT NULL,
    firmware_version VARCHAR(32) NOT NULL,
    modbus_ip INET NOT NULL,
    modbus_port INTEGER NOT NULL DEFAULT 502 CHECK (modbus_port > 0 AND modbus_port <= 65535),
    is_data_diode_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 3. Table de Télémétrie Haute Fréquence - Four de Trempe
CREATE TABLE IF NOT EXISTS ot_data.furnace_telemetry (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    line_id UUID NOT NULL REFERENCES ot_data.production_lines(id) ON DELETE RESTRICT,
    batch_id UUID NULL,
    temp_zone1_c NUMERIC(5,1) NOT NULL CHECK (temp_zone1_c BETWEEN 0.0 AND 850.0),
    temp_zone2_c NUMERIC(5,1) NOT NULL CHECK (temp_zone2_c BETWEEN 0.0 AND 850.0),
    temp_zone3_c NUMERIC(5,1) NOT NULL CHECK (temp_zone3_c BETWEEN 0.0 AND 850.0),
    temp_zone4_c NUMERIC(5,1) NOT NULL CHECK (temp_zone4_c BETWEEN 0.0 AND 850.0),
    glass_pyrometer_temp_c NUMERIC(5,1) NOT NULL CHECK (glass_pyrometer_temp_c BETWEEN 0.0 AND 850.0),
    quench_pressure_bar NUMERIC(4,2) NOT NULL CHECK (quench_pressure_bar BETWEEN 0.00 AND 12.00),
    conveyor_speed_m_min NUMERIC(4,2) NOT NULL CHECK (conveyor_speed_m_min BETWEEN 0.00 AND 50.00),
    blower_current_amps NUMERIC(5,1) NOT NULL DEFAULT 0.0,
    power_consumption_kw NUMERIC(6,2) NOT NULL DEFAULT 0.0,
    emergency_stop_tripped BOOLEAN NOT NULL DEFAULT FALSE,
    plc_status_flags INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Partition initiale par défaut pour la télémétrie four
CREATE TABLE IF NOT EXISTS ot_data.furnace_telemetry_y2026m10 PARTITION OF ot_data.furnace_telemetry
    FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');

CREATE TABLE IF NOT EXISTS ot_data.furnace_telemetry_default PARTITION OF ot_data.furnace_telemetry
    DEFAULT;

CREATE INDEX IF NOT EXISTS idx_furnace_telemetry_timestamp ON ot_data.furnace_telemetry (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_furnace_telemetry_line_time ON ot_data.furnace_telemetry (line_id, timestamp DESC);

-- 4. Table de Télémétrie - Autoclave de Feuilletage
CREATE TABLE IF NOT EXISTS ot_data.autoclave_telemetry (
    id BIGSERIAL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    line_id UUID NOT NULL REFERENCES ot_data.production_lines(id) ON DELETE RESTRICT,
    batch_id UUID NULL,
    vessel_pressure_bar NUMERIC(4,2) NOT NULL CHECK (vessel_pressure_bar BETWEEN 0.00 AND 16.00),
    vessel_temp_c NUMERIC(5,1) NOT NULL CHECK (vessel_temp_c BETWEEN 0.0 AND 200.0),
    vacuum_bag_level_mbar NUMERIC(5,1) NOT NULL CHECK (vacuum_bag_level_mbar BETWEEN 0.0 AND 1013.0),
    cycle_phase VARCHAR(24) NOT NULL CHECK (cycle_phase IN ('IDLE', 'VACUUM', 'HEATING_RAMP', 'DWELL_SOAK', 'COOLING', 'DEPRESSURIZING')),
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE IF NOT EXISTS ot_data.autoclave_telemetry_y2026m10 PARTITION OF ot_data.autoclave_telemetry
    FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');

CREATE TABLE IF NOT EXISTS ot_data.autoclave_telemetry_default PARTITION OF ot_data.autoclave_telemetry
    DEFAULT;

CREATE INDEX IF NOT EXISTS idx_autoclave_telemetry_timestamp ON ot_data.autoclave_telemetry (timestamp DESC);

-- 5. Contrôle Qualité Scanner Optique (Contraintes & Inclusions de Sulfure de Nickel)
CREATE TABLE IF NOT EXISTS ot_data.quality_defects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    line_id UUID NOT NULL REFERENCES ot_data.production_lines(id) ON DELETE RESTRICT,
    batch_id UUID NULL,
    defect_type VARCHAR(32) NOT NULL CHECK (defect_type IN (
        'ROLLER_WAVE',
        'EDGE_LIFT',
        'NICKEL_SULFIDE_INCLUSION',
        'SURFACE_SCRATCH',
        'OPTICAL_DISTORTION',
        'BUBBLE_PVB'
    )),
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'CRITICAL')),
    coord_x_mm NUMERIC(6,1) NOT NULL,
    coord_y_mm NUMERIC(6,1) NOT NULL,
    optical_scanner_id VARCHAR(32) NOT NULL,
    action_taken VARCHAR(24) NOT NULL CHECK (action_taken IN ('REJECTED', 'FLAGGED', 'ACCEPTED'))
);

CREATE INDEX IF NOT EXISTS idx_quality_defects_time ON ot_data.quality_defects (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_quality_defects_batch ON ot_data.quality_defects (batch_id);

-- 6. Journal d'Ingestion de la Data Diode Logique
CREATE TABLE IF NOT EXISTS ot_data.diode_import_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transmission_id UUID NOT NULL UNIQUE,
    source_gateway VARCHAR(64) NOT NULL,
    records_ingested INTEGER NOT NULL CHECK (records_ingested >= 0),
    packet_sha256 CHAR(64) NOT NULL,
    ed25519_signature TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_diode_import_tx ON ot_data.diode_import_log (transmission_id);

-- ============================================================================
-- VERROU D'IMMUABILITÉ (Append-Only Enforcement)
-- Empêche l'altération ou la suppression rétroactive des données de procédé
-- ============================================================================
CREATE OR REPLACE FUNCTION ot_data.fn_prevent_telemetry_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'VIOLATION DE SÉCURITÉ : La télémétrie industrielle (Niveau OT) est strictement append-only (immutabilité garantie).';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_furnace_telemetry_immutable
    BEFORE UPDATE OR DELETE ON ot_data.furnace_telemetry
    FOR EACH ROW EXECUTE FUNCTION ot_data.fn_prevent_telemetry_mutation();

CREATE TRIGGER trg_autoclave_telemetry_immutable
    BEFORE UPDATE OR DELETE ON ot_data.autoclave_telemetry
    FOR EACH ROW EXECUTE FUNCTION ot_data.fn_prevent_telemetry_mutation();

CREATE TRIGGER trg_diode_log_immutable
    BEFORE UPDATE OR DELETE ON ot_data.diode_import_log
    FOR EACH ROW EXECUTE FUNCTION ot_data.fn_prevent_telemetry_mutation();
