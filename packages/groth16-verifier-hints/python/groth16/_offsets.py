"""Selected-offset preprocessing with the shared 2*M*(S+1)+1 bound."""

import json
from . import _preprocess as g

PROTOCOL = g.params["protocol"]
q = g.q


def candidate_count(n):
    return 2 * (PROTOCOL["bases_per_input"] * n) * (PROTOCOL["windows"] + 1) + 1


def half(p):
    return (
        g.gp(p, "Half")
        if p is not None
        else "Half{x:Fp::zero(),y:Fp::zero(),is_infinity:true}"
    )


def pack_pair(o, j):
    coords = [*o, *(j if j is not None else [0, 0])]
    ls = [g.limbs(x) for x in coords]
    return [a[0] + (a[1] << 120) for a in ls] + [
        sum(a[2] << (14 * i) for i, a in enumerate(ls)) + (int(j is None) << 56)
    ]


def initial_offset():
    return tuple(map(int, g.params["initialOffset"]))


def make_pairs(correction, n):
    if n == 0:
        return [[0] * 5], []
    initial = initial_offset()
    O = None
    rows = []
    records = []
    seen = set()
    shift = 1 << (4 * (PROTOCOL["windows"] - 1))
    for _ in range(candidate_count(n)):
        O = g.add(O, initial)
        g.require(
            O is not None and O not in seen,
            "Offset origins must be finite and distinct",
        )
        seen.add(O)
        g.point(O)
        F = g.mul(shift, O)
        J = g.add(correction, (F[0], -F[1] % q))
        g.require(g.add(J, F) == correction, "Offset row must satisfy J + 2^60 O = K")
        if J is not None:
            g.point(J)
        rows.append(pack_pair(O, J))
        records.append({"origin": O, "correction": J})
    return rows, records


def methods(correction, n):
    rows, records = make_pairs(correction, n)
    O = initial_offset()
    F = g.mul(1 << (4 * (PROTOCOL["windows"] - 1)), O)
    legacy = g.add(correction, (F[0], -F[1] % q)) if n else correction
    source = " fn msm_correction_including_offset()->Half {" + half(legacy) + "}\n"
    source += (
        " fn msm_offset_pairs()->[[Field;5];"
        + str(candidate_count(n))
        + "] {["
        + ",".join(json.dumps(row) for row in rows)
        + "]}\n"
    )
    return source, records
