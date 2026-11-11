// Candidate count is 2*M*(S+1)+1.
// For M=4*N chunk bases and S=16 windows, M*(S+1)=68*N guarded
// additions include every skew candidate, even when its Boolean is false.
// Before a guard A=[2^k]O+T; x(A)=x(D) implies A=+/-D. In prime-order
// BN254 G1, [2^k] is invertible, excluding at most two origins per guard.
// Therefore 136*N+1 distinct finite trusted origins suffice. Finite distinct-x
// additions and odd-order doublings stay finite; complete final correction
// adds no exclusions. Changing S, M or the guard schedule requires a new count.
pub global WINDOWS: u32 = 16;
pub global BASES_PER_INPUT: u32 = 4;
pub global OFFSET_FACTOR: u32 = 136;
