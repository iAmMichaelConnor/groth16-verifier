export interface HintWorkerScope {
    addEventListener(type: "message", listener: (event: MessageEvent) => void): void;
    postMessage(message: unknown, transfer: Transferable[]): void;
}
/** Own one authenticated WASM instance. Serialize messages; any failure poisons this host. */
export declare function installWasmWorker(scope: HintWorkerScope): void;
