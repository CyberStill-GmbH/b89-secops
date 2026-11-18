type GetPage = (path: string) => Promise<{ status: number; body: unknown }>;

/** Resolve the emitted alert to its own case, including cases outside the live window. */
export async function findEmittingCandidate(
  get: GetPage,
  alert: { id: string; reasons: readonly { code: string; detail: string }[] },
): Promise<Record<string, unknown> | undefined> {
  const prefix = 'Expediente del correlador: ';
  const reference = alert.reasons.find(reason =>
    reason.code === 'CORRELATED_ENTITY' && reason.detail.startsWith(prefix));
  const id = reference?.detail.slice(prefix.length);
  if (id !== undefined && !/^rc_[0-9a-f]{24}$/.test(id)) {
    throw new Error('INVALID_CANDIDATE_REFERENCE');
  }
  const path = id ? '/v1/candidates/' + id : '/v1/candidates-by-alert/' + encodeURIComponent(alert.id);
  const response = await get(path);
  if (response.status === 404) return undefined;
  if (response.status !== 200) throw new Error('CORRELATOR_UNAVAILABLE');
  const item = response.body as Record<string, unknown> | null;
  if (typeof item?.id !== 'string' || !/^rc_[0-9a-f]{24}$/.test(item.id) ||
      (id && item.id !== id) ||
      ((!id || item.alertId) && item.alertId !== alert.id)) {
    throw new Error('CANDIDATE_REFERENCE_MISMATCH');
  }
  return item;
}

/** Read a stable prefix of the append-only membership list as of the first page. */
export async function readCandidateMembers(get: GetPage, id: string, signal?: AbortSignal, kind: 'alerts' | 'observations' = 'alerts'): Promise<string[]> {
  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(id)) throw new Error('INVALID_CANDIDATE_ID');
  const ids = new Set<string>();
  let total: number | undefined;
  let offset = 0;
  do {
    signal?.throwIfAborted();
    const { status, body } = await get(`/v1/candidates/${id}/members?offset=${offset}&limit=100&kind=${kind}`);
    if (status !== 200 || !body || typeof body !== 'object') throw new Error('MEMBERS_UNAVAILABLE');
    const page = body as Record<string, unknown>;
    if (!Number.isSafeInteger(page.total) || Number(page.total) < (total ?? 0) || !Array.isArray(page.items)) {
      throw new Error('INVALID_MEMBERS_PAGE');
    }
    total ??= Number(page.total);
    if (page.items.length > 100 || offset + page.items.length > Number(page.total)) throw new Error('INVALID_MEMBERS_PAGE');
    for (const item of page.items.slice(0, total - offset)) {
      if (typeof item !== 'string' || !item || ids.has(item)) throw new Error('INVALID_MEMBER');
      ids.add(item);
    }
    offset += page.items.length;
    if (offset < total && (!page.items.length || page.nextOffset !== offset)) throw new Error('INCOMPLETE_MEMBERS');
  } while (offset < total);
  return [...ids];
}
