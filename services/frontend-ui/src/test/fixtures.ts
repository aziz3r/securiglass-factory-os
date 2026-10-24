import { vi } from 'vitest';

import type {
  ApiPort,
  AuditLog,
  AuditVerifyResult,
  CurrentUser,
  Customer,
  CustomerCreateInput,
  TokenResponse,
} from '../api/types';
import type {
  SocketStatus,
  SocketStatusDetail,
  TelemetrySample,
  TelemetrySocket,
  TelemetrySocketHandlers,
} from '../realtime/telemetrySocket';

export const FIXED_NOW = 1_760_000_000_000;

export const TOKEN_RESPONSE: TokenResponse = {
  access_token: 'eyJ.test-token-never-persisted',
  token_type: 'bearer',
  expires_in: 1800,
};

export const SUPER_ADMIN: CurrentUser = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'admin',
  email: 'admin@securiglass.local',
  roles: ['SUPER_ADMIN'],
  clearance_level: 5,
};

export const SECURITY_AUDITOR: CurrentUser = {
  id: '22222222-2222-4222-8222-222222222222',
  username: 'auditor',
  email: 'auditor@securiglass.local',
  roles: ['SECURITY_AUDITOR'],
  clearance_level: 4,
};

export const PLANT_MANAGER: CurrentUser = {
  id: '33333333-3333-4333-8333-333333333333',
  username: 'manager',
  email: 'manager@securiglass.local',
  roles: ['PLANT_MANAGER'],
  clearance_level: 3,
};

export const OT_OPERATOR: CurrentUser = {
  id: '44444444-4444-4444-8444-444444444444',
  username: 'operator',
  email: 'operator@securiglass.local',
  roles: ['OT_OPERATOR'],
  clearance_level: 2,
};

export const QUALITY_INSPECTOR: CurrentUser = {
  id: '55555555-5555-4555-8555-555555555555',
  username: 'quality',
  email: 'quality@securiglass.local',
  roles: ['QUALITY_INSPECTOR'],
  clearance_level: 2,
};

export const CUSTOMER: Customer = {
  id: '66666666-6666-4666-8666-666666666666',
  company_name: 'Vitrerie du Rhône',
  contact_name: 'Camille Martin',
  email: 'camille@vitrerie.example',
  phone: '+33 4 72 00 00 00',
  vat_number: 'FR12345678901',
  country_code: 'FR',
  is_active: true,
  created_at: '2026-10-20T10:00:00Z',
};

export const SECOND_CUSTOMER: Customer = {
  ...CUSTOMER,
  id: '77777777-7777-4777-8777-777777777777',
  company_name: 'Glass Solutions GmbH',
  contact_name: 'Alex Weber',
  email: 'alex@glass.example',
  phone: null,
  vat_number: null,
  country_code: 'DE',
};

export const AUDIT_LOG: AuditLog = {
  id: '88888888-8888-4888-8888-888888888888',
  event_time: '2026-10-24T10:15:00Z',
  event_type: 'AUTH_LOGIN_SUCCESS',
  actor_username: 'manager',
  actor_ip: '10.10.20.10',
  action: 'LOGIN',
  resource: 'sec_data.users',
  outcome: 'SUCCESS',
  details: { method: 'password' },
  prev_log_hash: null,
  current_hash: 'a'.repeat(64),
};

export const VERIFY_OK: AuditVerifyResult = {
  chain_valid: true,
  first_broken_id: null,
  total_records_checked: 42,
};

export interface FakeApi {
  api: ApiPort;
  login: ReturnType<typeof vi.fn>;
  logout: ReturnType<typeof vi.fn>;
  me: ReturnType<typeof vi.fn>;
  listCustomers: ReturnType<typeof vi.fn>;
  createCustomer: ReturnType<typeof vi.fn>;
  listAuditLogs: ReturnType<typeof vi.fn>;
  verifyAuditChain: ReturnType<typeof vi.fn>;
  health: ReturnType<typeof vi.fn>;
}

export function createFakeApi(user: CurrentUser = PLANT_MANAGER): FakeApi {
  const login = vi.fn(async () => TOKEN_RESPONSE);
  const logout = vi.fn(async () => undefined);
  const me = vi.fn(async () => user);
  const listCustomers = vi.fn(async () => [CUSTOMER] as Customer[]);
  const createCustomer = vi.fn(
    async (_token: string, input: CustomerCreateInput): Promise<Customer> => ({
      ...CUSTOMER,
      id: '99999999-9999-4999-8999-999999999999',
      company_name: input.company_name,
      contact_name: input.contact_name,
      email: input.email,
      phone: input.phone ?? null,
      vat_number: input.vat_number ?? null,
      country_code: input.country_code,
    }),
  );
  const listAuditLogs = vi.fn(async () => [AUDIT_LOG] as AuditLog[]);
  const verifyAuditChain = vi.fn(async () => VERIFY_OK);
  const health = vi.fn(async () => ({
    status: 'UP',
    service: 'securiglass-backend-api',
    version: '1.0.0',
    environment: 'test',
  }));

  const api: ApiPort = {
    login,
    logout,
    me,
    listCustomers,
    createCustomer,
    listAuditLogs,
    verifyAuditChain,
    health,
  };

  return {
    api,
    login,
    logout,
    me,
    listCustomers,
    createCustomer,
    listAuditLogs,
    verifyAuditChain,
    health,
  };
}

export interface FakeSocketHarness {
  factory: (handlers: TelemetrySocketHandlers) => TelemetrySocket;
  connect: ReturnType<typeof vi.fn>;
  disconnect: ReturnType<typeof vi.fn>;
  emitStatus: (status: SocketStatus, detail?: Partial<SocketStatusDetail>) => void;
  emitSample: (sample: TelemetrySample) => void;
  getToken: () => (() => string | null) | null;
}

export function createFakeSocket(): FakeSocketHarness {
  let handlers: TelemetrySocketHandlers | null = null;
  let tokenGetter: (() => string | null) | null = null;
  const connect = vi.fn((getToken: () => string | null) => {
    tokenGetter = getToken;
  });
  const disconnect = vi.fn();
  const socket: TelemetrySocket = {
    status: 'idle',
    connect,
    disconnect,
  };
  const factory = (nextHandlers: TelemetrySocketHandlers): TelemetrySocket => {
    handlers = nextHandlers;
    return socket;
  };

  return {
    factory,
    connect,
    disconnect,
    emitStatus(status, detail = {}) {
      handlers?.onStatus(status, {
        attempt: detail.attempt ?? 0,
        nextRetryMs: detail.nextRetryMs ?? null,
        error: detail.error ?? null,
      });
    },
    emitSample(sample) {
      handlers?.onSample(sample);
    },
    getToken() {
      return tokenGetter;
    },
  };
}

export const TELEMETRY_SAMPLE: TelemetrySample = {
  furnaceTempC: 712.5,
  glassThicknessMm: 6,
  lineSpeedMps: 1.2,
  timestamp: '2026-10-24T10:20:00Z',
};
