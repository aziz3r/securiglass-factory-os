/**
 * Validation d'exécution des réponses API (zero-trust côté client).
 *
 * TypeScript ne protège pas des réponses réseau malformées : chaque réponse est
 * contrôlée avant d'entrer dans le store. Toute anomalie lève ProtocolError.
 */

import { ProtocolError } from './errors';
import type {
  AuditLog,
  AuditVerifyResult,
  CurrentUser,
  Customer,
  HealthStatus,
  TokenResponse,
} from './types';
import { normalizeRoles } from '../security/roles';

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ProtocolError(`${label} : objet attendu`);
  }
  return value as Record<string, unknown>;
}

function asArray(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new ProtocolError(`${label} : tableau attendu`);
  }
  return value;
}

function readString(
  record: Record<string, unknown>,
  key: string,
  label: string,
): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new ProtocolError(`${label} : chaîne non vide attendue (${key})`);
  }
  return value;
}

function readNullableString(
  record: Record<string, unknown>,
  key: string,
  label: string,
): string | null {
  const value = record[key];
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    throw new ProtocolError(`${label} : chaîne ou null attendu (${key})`);
  }
  return value;
}

function readBoolean(
  record: Record<string, unknown>,
  key: string,
  label: string,
): boolean {
  const value = record[key];
  if (typeof value !== 'boolean') {
    throw new ProtocolError(`${label} : booléen attendu (${key})`);
  }
  return value;
}

function readFiniteNumber(
  record: Record<string, unknown>,
  key: string,
  label: string,
): number {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ProtocolError(`${label} : nombre fini attendu (${key})`);
  }
  return value;
}

export function parseTokenResponse(raw: unknown): TokenResponse {
  const record = asRecord(raw, 'Token');
  const token = readString(record, 'access_token', 'Token');
  const tokenType = readString(record, 'token_type', 'Token');
  const expiresIn = readFiniteNumber(record, 'expires_in', 'Token');
  if (expiresIn <= 0) {
    throw new ProtocolError('Token : durée de vie invalide');
  }
  return {
    access_token: token,
    token_type: tokenType,
    expires_in: expiresIn,
  };
}

export function parseCurrentUser(raw: unknown): CurrentUser {
  const record = asRecord(raw, 'Profil');
  const id = readString(record, 'id', 'Profil');
  const username = readString(record, 'username', 'Profil');
  const email = readString(record, 'email', 'Profil');
  const rawRoles = asArray(record['roles'], 'Profil.roles');
  const roles = normalizeRoles(rawRoles);
  if (roles.length === 0) {
    throw new ProtocolError('Profil : aucun rôle exploitable');
  }
  const clearance = readFiniteNumber(record, 'clearance_level', 'Profil');
  if (!Number.isInteger(clearance) || clearance < 1 || clearance > 5) {
    throw new ProtocolError('Profil : niveau d’habilitation invalide');
  }
  return {
    id,
    username,
    email,
    roles,
    clearance_level: clearance,
  };
}

export function parseCustomer(raw: unknown): Customer {
  const record = asRecord(raw, 'Client');
  return {
    id: readString(record, 'id', 'Client'),
    company_name: readString(record, 'company_name', 'Client'),
    contact_name: readString(record, 'contact_name', 'Client'),
    email: readString(record, 'email', 'Client'),
    phone: readNullableString(record, 'phone', 'Client'),
    vat_number: readNullableString(record, 'vat_number', 'Client'),
    country_code: readString(record, 'country_code', 'Client'),
    is_active: readBoolean(record, 'is_active', 'Client'),
    created_at: readNullableString(record, 'created_at', 'Client'),
  };
}

export function parseCustomerList(raw: unknown): Customer[] {
  return asArray(raw, 'Clients').map((item) => parseCustomer(item));
}

function parseDetails(raw: unknown): Record<string, unknown> | null {
  if (raw === null || raw === undefined) {
    return null;
  }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ProtocolError('Audit : détails objets attendus');
  }
  return raw as Record<string, unknown>;
}

export function parseAuditLog(raw: unknown): AuditLog {
  const record = asRecord(raw, 'Audit');
  return {
    id: readString(record, 'id', 'Audit'),
    event_time: readString(record, 'event_time', 'Audit'),
    event_type: readString(record, 'event_type', 'Audit'),
    actor_username: readString(record, 'actor_username', 'Audit'),
    actor_ip: readString(record, 'actor_ip', 'Audit'),
    action: readString(record, 'action', 'Audit'),
    resource: readString(record, 'resource', 'Audit'),
    outcome: readString(record, 'outcome', 'Audit'),
    details: parseDetails(record['details']),
    prev_log_hash: readNullableString(record, 'prev_log_hash', 'Audit'),
    current_hash: readString(record, 'current_hash', 'Audit'),
  };
}

export function parseAuditLogList(raw: unknown): AuditLog[] {
  return asArray(raw, 'Audit').map((item) => parseAuditLog(item));
}

export function parseAuditVerify(raw: unknown): AuditVerifyResult {
  const record = asRecord(raw, 'Vérification audit');
  const total = readFiniteNumber(record, 'total_records_checked', 'Vérification');
  if (!Number.isInteger(total) || total < 0) {
    throw new ProtocolError('Vérification : total invalide');
  }
  return {
    chain_valid: readBoolean(record, 'chain_valid', 'Vérification'),
    first_broken_id: readNullableString(record, 'first_broken_id', 'Vérification'),
    total_records_checked: total,
  };
}

export function parseHealth(raw: unknown): HealthStatus {
  const record = asRecord(raw, 'Santé');
  return {
    status: readString(record, 'status', 'Santé'),
    service: readString(record, 'service', 'Santé'),
    version: readString(record, 'version', 'Santé'),
    environment: readString(record, 'environment', 'Santé'),
  };
}

/**
 * Extrait les erreurs de champ Pydantic (`body -> email`) en clés simples.
 * Les messages sont affichés comme texte React (jamais de HTML).
 */
export function parseFieldErrors(raw: unknown): Record<string, string> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return {};
  }
  const record = raw as Record<string, unknown>;
  const errors = record['errors'];
  if (!Array.isArray(errors)) {
    return {};
  }
  const result: Record<string, string> = {};
  for (const item of errors) {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      continue;
    }
    const entry = item as Record<string, unknown>;
    const field = entry['field'];
    const message = entry['message'];
    if (typeof field !== 'string' || typeof message !== 'string') {
      continue;
    }
    const segments = field.split('->');
    const key = segments[segments.length - 1]?.trim() ?? '';
    if (key.length > 0 && key !== 'body' && key !== '') {
      result[key] = message.slice(0, 300);
    }
  }
  return result;
}
