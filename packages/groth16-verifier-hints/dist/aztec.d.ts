/** Optional Aztec v6 integration. Inject the application's existing SDK classes;
 * this module neither loads a second backend nor submits transactions. */
import { type PreparedRequest } from './current.js';
export interface FieldLike {
    toBigInt(): bigint;
}
export interface AddressLike {
    toField(): FieldLike;
}
export interface AztecTypes<F extends FieldLike, A extends AddressLike, C> {
    readonly Fr: new (value: bigint) => F;
    readonly AztecAddress: {
        readonly ZERO: A;
    };
    readonly Capsule: new (contractAddress: A, storageSlot: F, data: F[], scope?: A) => C;
}
export interface CapsuleInteraction<C, I> {
    with(options: {
        capsules: C[];
    }): I;
}
export interface GeneratedContract<A extends AddressLike, C, I> {
    readonly address: A;
    readonly methods: {
        verify(...args: any[]): I & CapsuleInteraction<C, I>;
    };
}
/** Attach untrusted witnesses to precisely the address bound into the statement.
 * Return a normal SDK interaction; the application chooses simulate/prove/send.
 * The generated contract independently checks chain, version and its address.
 */
export declare function preparePrivateCall<F extends FieldLike, A extends AddressLike, C, I>(profile: unknown, packet: PreparedRequest, contract: GeneratedContract<A, C, I>, sdk: AztecTypes<F, A, C>): I;
import { type ProducerCertificate } from './producer.js';
/** Prepare the O consumer call after local producer-proof verification. The
 * contract's immutable producer-key policy remains the authorization boundary. */
export declare function prepareOffchainCall<A extends AddressLike, C, I>(profile: unknown, packet: PreparedRequest, certificate: ProducerCertificate, contract: GeneratedContract<A, C, I>, approvedProducerKeyHash: bigint): I & CapsuleInteraction<C, I>;
