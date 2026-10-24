import type { Role } from '../security/roles';

/** Contrats de l'API FastAPI (préfixe /api/v1). */

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface CurrentUser {
  id: string;
  username: string;
  email: string;
  roles: Role[];
  clearance_level: number;
}

export interface Customer {
  id: string;
  company_name: string;
  contact_name: string;
  email: string;
  phone: string | null;
  vat_number: string | null;
  country_code: string;
  is_active: boolean;
  created_at: string | null;
}

export interface CustomerCreateInput {
  company_name: string;
  contact_name: string;
  email: string;
  phone?: string;
  vat_number?: string;
  country_code: string;
}

export interface AuditLog {
  id: string;
  event_time: string;
  event_type: string;
  actor_username: string;
  actor_ip: string;
  action: string;
  resource: string;
  outcome: string;
  details: Record<string, unknown> | null;
  prev_log_hash: string | null;
  current_hash: string;
}

export interface AuditVerifyResult {
  chain_valid: boolean;
  first_broken_id: string | null;
  total_records_checked: number;
}

export interface AuditListParams {
  limit?: number;
  offset?: number;
  eventType?: string;
}

export interface ListParams {
  limit?: number;
  offset?: number;
}

export interface HealthStatus {
  status: string;
  service: string;
  version: string;
  environment: string;
}

/**
 * Port utilisé par le store. Le jeton est passé explicitement à chaque appel :
 * le client HTTP ne conserve AUCUN état d'authentification.
 */
export interface ApiPort {
  login(credentials: LoginCredentials): Promise<TokenResponse>;
  logout(token: string): Promise<void>;
  me(token: string): Promise<CurrentUser>;
  listCustomers(token: string, params?: ListParams): Promise<Customer[]>;
  createCustomer(token: string, input: CustomerCreateInput): Promise<Customer>;
  listAuditLogs(token: string, params?: AuditListParams): Promise<AuditLog[]>;
  verifyAuditChain(token: string): Promise<AuditVerifyResult>;
  health(): Promise<HealthStatus>;
}

export type FetchLike = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;
