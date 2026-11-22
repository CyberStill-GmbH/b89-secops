export interface DlpPolicyRecord {
  readonly tenantId: string;
  readonly document: unknown;
  readonly revision: number;
  readonly updatedAt: Date;
  readonly updatedBy: string;
}

export interface DlpEndpointRecord {
  readonly id: string;
  readonly tenantId: string;
  readonly hostname: string | null;
  readonly agentId: string | null;
  readonly enrolledAt: Date | null;
  readonly lastSeenAt: Date | null;
  readonly revokedAt: Date | null;
  readonly appliedRevision: number;
  readonly credentialVersion: number;
  readonly policyVersion: string | null;
  readonly enrollmentExpiresAt: Date;
}

export interface DlpPolicyStore {
  policy(tenantId: string): Promise<DlpPolicyRecord | undefined>;
  putPolicy(
    tenantId: string,
    document: unknown,
    expectedRevision: number,
    updatedBy: string,
    updatedAt: Date,
  ): Promise<boolean>;
  issueEnrollmentToken(input: {
    id: string;
    tenantId: string;
    tokenHash: string;
    expiresAt: Date;
    now: Date;
  }): Promise<boolean>;
  enrollEndpoint(input: {
    tenantId: string;
    tokenHash: string;
    credentialHash: string;
    hostname: string;
    agentId: string;
    at: Date;
  }): Promise<DlpEndpointRecord | undefined>;
  endpointByToken(input: {
    tenantId: string;
    tokenHash: string;
    at: Date;
  }): Promise<DlpEndpointRecord | undefined>;
  acknowledgePolicy(input: {
    endpointId: string;
    tenantId: string;
    revision: number;
    policyVersion: string;
    at: Date;
  }): Promise<boolean>;
  endpoints(tenantId: string): Promise<readonly DlpEndpointRecord[]>;
  revokeEndpoint(input: { tenantId: string; id: string; at: Date }): Promise<boolean>;
}
