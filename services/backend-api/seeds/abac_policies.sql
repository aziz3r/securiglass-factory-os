-- Politiques ABAC (correctif D1). Sémantique du moteur (app/services/abac_engine.py) :
-- ALLOW = accès accordé si la condition (contexte autorisé) est vraie ; DENY = refus si
-- la condition (contexte interdit) est vraie ; sinon refus par défaut.
INSERT INTO sec_data.abac_policies (policy_name, effect, subject_role, action_verb, resource_urn, rule_condition, description) VALUES
('ABAC_01_OPERATOR_CONTROL_WRITE', 'ALLOW', 'OT_OPERATOR', 'ot:control:write', 'urn:securiglass:ot:*',
 '{"and":[{"in_cidr":{"client_ip":"10.10.20.0/24"}},{"time_between":{"start":"05:45:00","end":"22:15:00"}},{"equals":{"environment.maintenance_lock":false}}]}',
 'Opérateur OT : salle de contrôle, plage horaire, hors maintenance'),
('ABAC_01_OPERATOR_RECIPE_SELECT', 'ALLOW', 'OT_OPERATOR', 'ot:recipe:select', 'urn:securiglass:it:recipe:*',
 '{"and":[{"in_cidr":{"client_ip":"10.10.20.0/24"}},{"time_between":{"start":"05:45:00","end":"22:15:00"}},{"equals":{"environment.maintenance_lock":false}}]}',
 'Opérateur OT : sélection de recette'),
('ABAC_01_OPERATOR_BATCH_STATUS', 'ALLOW', 'OT_OPERATOR', 'it:batch:update_status', 'urn:securiglass:it:batch:*',
 '{"and":[{"in_cidr":{"client_ip":"10.10.20.0/24"}},{"time_between":{"start":"05:45:00","end":"22:15:00"}},{"equals":{"environment.maintenance_lock":false}}]}',
 'Opérateur OT : changement de statut de lot'),
('ABAC_02_EDGE_MTLS', 'ALLOW', 'SERVICE_ACCOUNT_EDGE', 'ot:telemetry:insert', 'urn:securiglass:ot:telemetry:*',
 '{"and":[{"in_cidr":{"client_ip":"10.10.30.0/24"}},{"equals":{"client_cert.issuer":"CN=SecuriGlass-OT-CA,O=SecuriGlass"}},{"equals":{"client_cert.san_dns":"edge-gateway.ot.local"}},{"not_in":{"client_cert.serial":"REVOKED_CERTS_LIST"}}]}',
 'Edge Gateway : mTLS strict'),
('ABAC_02_EDGE_REVOKED_DENY', 'DENY', '*', 'ot:telemetry:insert', 'urn:securiglass:ot:telemetry:*',
 '{"in":{"client_cert.serial":"REVOKED_CERTS_LIST"}}',
 'Blocage dur : certificat révoqué'),
('ABAC_03_FOUR_EYES_RECIPE', 'ALLOW', 'PLANT_MANAGER', 'it:recipe:approve', 'urn:securiglass:it:recipe:*',
 '{"and":[{"not_equals":{"subject.user_id":"resource.recipe.created_by"}},{"greater_or_equal":{"subject.clearance_level":3}}]}',
 'Quatre yeux : pas d auto-approbation'),
('ABAC_03_FOUR_EYES_DENY', 'DENY', '*', 'it:recipe:approve', 'urn:securiglass:it:recipe:*',
 '{"equals":{"subject.user_id":"resource.recipe.created_by"}}',
 'Blocage dur : auto-approbation')
ON CONFLICT (policy_name) DO NOTHING;
