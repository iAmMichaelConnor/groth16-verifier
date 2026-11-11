/** Optional owned browser Worker client. The main thread retains profile/packet provenance. */
import { parseProfile } from "./current.js";
import type { PreparedKernel } from "./wasm.js";

export interface OwnedWorkerKernel {
  readonly kernel: PreparedKernel;
  /** Idempotent: rejects pending work and terminates only this client's owned Worker. */
  dispose(): void;
}

/** The factory must create a NEW dedicated Worker, whose ownership transfers to this client.
 * Caller buffers are copied before transfer. No Worker, fetch or WASM load occurs on import.
 */
export async function createWasmWorkerKernel(
  profile: unknown,
  bytes: Uint8Array,
  workerFactory: () => Worker,
  options: { timeoutMs?: number } = {},
): Promise<OwnedWorkerKernel> {
  const parsed = parseProfile(profile);
  if (!(bytes instanceof Uint8Array))
    throw new Error("WASM bytes must be a Uint8Array");
  const timeoutMs = options.timeoutMs ?? 60_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0)
    throw new Error("Worker timeout must be a positive integer");
  const worker = workerFactory();
  type Pending = {
    kind: "init" | "run";
    resolve: (output: ArrayBuffer | undefined) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  };
  const pending = new Map<number, Pending>();
  let nextId = 0;
  let closed: Error | undefined;
  function close(error: Error) {
    if (closed) return;
    closed = error;
    worker.removeEventListener("message", message);
    worker.removeEventListener("error", failed);
    worker.removeEventListener("messageerror", unreadable);
    worker.terminate();
    for (const item of pending.values()) {
      clearTimeout(item.timer);
      item.reject(error);
    }
    pending.clear();
  }
  function message(event: MessageEvent) {
    const data = event.data;
    const item =
      data && Number.isSafeInteger(data.id) ? pending.get(data.id) : undefined;
    if (!item || typeof data.ok !== "boolean") {
      close(new Error("Invalid hint Worker response"));
      return;
    }
    if (!data.ok) {
      close(
        new Error(
          typeof data.error === "string" ? data.error : "Hint Worker failed",
        ),
      );
      return;
    }
    const output = data.output;
    if (
      (item.kind === "init" && output !== undefined) ||
      (item.kind === "run" &&
        (!(output instanceof ArrayBuffer) ||
          output.byteLength !== (parsed.keyPolicy === "fixed" ? 29664 : 30240)))
    ) {
      close(new Error("Invalid hint Worker response bytes"));
      return;
    }
    clearTimeout(item.timer);
    pending.delete(data.id);
    item.resolve(output);
  }
  function failed(event: ErrorEvent) {
    close(
      new Error(`Hint Worker error: ${event.message || "execution failed"}`),
    );
  }
  function unreadable() {
    close(new Error("Hint Worker message could not be decoded"));
  }
  worker.addEventListener("message", message);
  worker.addEventListener("error", failed);
  worker.addEventListener("messageerror", unreadable);
  function request(
    kind: "init" | "run",
    payload: Record<string, unknown>,
    buffer: ArrayBuffer,
  ): Promise<ArrayBuffer | undefined> {
    if (closed) return Promise.reject(closed);
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => close(new Error("Hint Worker timed out")),
        timeoutMs,
      );
      pending.set(id, { kind, resolve, reject, timer });
      try {
        worker.postMessage({ id, kind, ...payload }, [buffer]);
      } catch (error) {
        close(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }
  const asset = Uint8Array.from(bytes);
  await request("init", { profile: parsed, bytes: asset.buffer }, asset.buffer);
  return Object.freeze({
    kernel: async (input: Uint8Array) => {
      if (!(input instanceof Uint8Array))
        throw new Error("Kernel input must be a Uint8Array");
      const owned = Uint8Array.from(input);
      const output = await request(
        "run",
        { bytes: owned.buffer },
        owned.buffer,
      );
      return new Uint8Array(output!);
    },
    dispose: () => close(new Error("Hint Worker disposed")),
  });
}
