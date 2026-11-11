/** Install only inside a dedicated Worker entry module; not an automatic side effect. */
import { createProfileWasmKernel } from "./wasm-assets.js";
/** Own one authenticated WASM instance. Serialize messages; any failure poisons this host. */
export function installWasmWorker(scope) {
    let kernel;
    let failed = false;
    let queue = Promise.resolve();
    scope.addEventListener("message", (event) => {
        queue = queue.then(async () => {
            const message = event.data;
            const id = message?.id;
            try {
                if (!Number.isSafeInteger(id) ||
                    id < 0 ||
                    !(message.bytes instanceof ArrayBuffer))
                    throw new Error("Invalid hint Worker request");
                if (failed)
                    throw new Error("Hint Worker failed; recreate it");
                if (message.kind === "init" && !kernel) {
                    kernel = await createProfileWasmKernel(message.profile, new Uint8Array(message.bytes));
                    scope.postMessage({ id, ok: true }, []);
                }
                else if (message.kind === "run" && kernel) {
                    const output = Uint8Array.from(await kernel(new Uint8Array(message.bytes)));
                    scope.postMessage({ id, ok: true, output: output.buffer }, [
                        output.buffer,
                    ]);
                }
                else
                    throw new Error("Hint Worker initialization/order mismatch");
            }
            catch (error) {
                failed = true;
                scope.postMessage({
                    id,
                    ok: false,
                    error: error instanceof Error ? error.message : String(error),
                }, []);
            }
        });
    });
}
