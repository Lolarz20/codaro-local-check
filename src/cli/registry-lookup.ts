import type { RegistryResult } from '../types.js';
/** Optional explicit npm existence lookup, separate from deterministic scans. Never called by CLI. */
export async function lookupPackage(name: string, options: { readonly endpoint: string; readonly allowedNames: readonly string[]; readonly fetch: typeof fetch; readonly timeoutMs?: number }): Promise<RegistryResult> {
  const result = (status: RegistryResult['status']): RegistryResult => ({ status, safety: 'not_assessed' });
  if (!options.allowedNames.includes(name)) return result('not_allowed');
  let endpoint: URL;
  try { endpoint = new URL(options.endpoint); } catch { return result('unavailable'); }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.search || endpoint.hash || !Number.isFinite(options.timeoutMs ?? 3000) || (options.timeoutMs ?? 3000) <= 0) return result('unavailable');
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const response = await Promise.race([
      options.fetch(new URL(encodeURIComponent(name), endpoint.href.endsWith('/') ? endpoint : new URL(endpoint.href + '/')).href, { method: 'HEAD', redirect: 'manual', signal: controller.signal }),
      new Promise<never>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error()); }, Math.min(options.timeoutMs ?? 3000, 30_000)); })
    ]);
    void response.body?.cancel().catch(() => {});
    return result(response.status === 404 ? 'missing' : response.ok ? 'exists' : 'unavailable');
  } catch { return result('unavailable'); }
  finally { if (timer) clearTimeout(timer); controller.abort(); }
}
