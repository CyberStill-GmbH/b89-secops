/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import type { B89ApiClient } from './client';

export interface DlpPolicy {
  readonly revision: number;
  readonly policyVersion: string;
  readonly enabledRuleIds: readonly string[];
  readonly fingerprintsSha256: readonly string[];
  readonly updatedAt: string | null;
}

export type DlpEndpointStatus = 'current' | 'offline' | 'updating' | 're-enrollment-required' | 'revoked';

export interface DlpEndpoint {
  readonly id: string;
  readonly hostname: string;
  readonly agentId: string | null;
  readonly status: DlpEndpointStatus;
  readonly enrolledAt?: string | null;
  readonly lastSeenAt: string | null;
  readonly currentRevision: number | null;
  readonly currentPolicyVersion: string | null;
  readonly revokedAt?: string | null;
}

export interface DlpEndpointsResponse {
  readonly policyRevision?: number;
  readonly onlineWindowSeconds?: number;
  readonly items: readonly DlpEndpoint[];
}

export interface DlpEnrollmentToken {
  /** Id de la fila: es también el id que tendrá el equipo al conectarse. */
  readonly id: string;
  readonly token: string;
  readonly expiresAt: string;
}

export interface DlpEnrollmentStatus {
  readonly id: string;
  readonly state: 'waiting' | 'connected' | 'expired' | 'revoked';
  readonly expiresAt: string;
  readonly endpoint: {
    readonly id: string;
    readonly hostname: string;
    readonly enrolledAt: string;
    readonly lastSeenAt: string | null;
  } | null;
}

export async function getDlpPolicy(api: B89ApiClient): Promise<DlpPolicy> {
  return api.get<DlpPolicy>('/dlp/policy');
}

export async function saveDlpPolicy(
  api: B89ApiClient,
  input: {
    readonly expectedRevision: number;
    readonly policyVersion: string;
    readonly enabledRuleIds: readonly string[];
    readonly fingerprintsSha256: readonly string[];
  },
): Promise<DlpPolicy> {
  return api.put<DlpPolicy>('/dlp/policy', input);
}

export async function getDlpEndpoints(api: B89ApiClient): Promise<DlpEndpointsResponse> {
  return api.get<DlpEndpointsResponse>('/dlp/endpoints');
}

export async function createDlpEnrollmentToken(api: B89ApiClient): Promise<DlpEnrollmentToken> {
  return api.post<DlpEnrollmentToken>('/dlp/enrollment-tokens', {});
}

export async function getDlpEnrollmentStatus(api: B89ApiClient, id: string): Promise<DlpEnrollmentStatus> {
  return api.get<DlpEnrollmentStatus>(`/dlp/enrollment-tokens/${encodeURIComponent(id)}`);
}

export async function cancelDlpEnrollmentToken(api: B89ApiClient, id: string): Promise<void> {
  await api.post(`/dlp/enrollment-tokens/${encodeURIComponent(id)}/cancel`, {});
}

export async function revokeDlpEndpoint(api: B89ApiClient, id: string): Promise<void> {
  await api.post(`/dlp/endpoints/${encodeURIComponent(id)}/revoke`, {});
}
