import type { loadWorkerEntrypointConfig } from '@b89/configuration';
import { WorkerRuntime, type WorkerEvent } from './lifecycle/worker-runtime.js';

export function composeWorker(
  _config: ReturnType<typeof loadWorkerEntrypointConfig>,
  emit: WorkerEvent,
) {
  return new WorkerRuntime(emit);
}
