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

export interface DlpEndpoint {
  readonly id: string;
  readonly hostname: string;
  readonly agentId: string | null;
  readonly status: 'current' | 'offline' | 'updating' | 're-enrollment-required' | 'revoked';
  readonly lastSeenAt: string | null;
  readonly currentRevision: number | null;
  readonly currentPolicyVersion: string | null;
  readonly revokedAt?: string | null;
}

export interface DlpEndpointsResponse {
  readonly items: readonly DlpEndpoint[];
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

export async function createDlpEnrollmentToken(
  api: B89ApiClient,
): Promise<{ readonly token: string; readonly expiresAt: string }> {
  return api.post('/dlp/enrollment-tokens', {});
}

export async function revokeDlpEndpoint(api: B89ApiClient, id: string): Promise<void> {
  await api.post(`/dlp/endpoints/${encodeURIComponent(id)}/revoke`, {});
}
