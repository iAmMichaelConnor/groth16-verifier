#!/usr/bin/env python3
"""SP1 v5 wire mapping and witness CLI using the generic Groth16 arithmetic.

The Python public-value mapping retains its variable-byte input domain. The
host SDK separately requires 32 bytes; neither host operation creates a proof.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import math
import random
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "packages/groth16-verifier-hints/python"))
from groth16._pairing import (
    Fp12,
    Fp2,
    Fp6,
    G1Affine,
    G2Affine,
    P,
    R,
    X,
    add_g1_jac,
    combine_eval_schedules,
    compute_b_schedule_with_witness,
    compute_line_schedule_raw,
    compute_t_preimage,
    cube_root,
    emit_fixed_lines_file,
    emit_fp12_noir,
    evaluate_schedule_at_p,
    final_exponentiation,
    find_root_27th,
    fp12_to_limb_list,
    fp_from_limbs,
    g1_affine_to_jac,
    jacobian_to_affine_g1,
    line_witness_to_payload,
    miller_loop,
    modinv,
    scalar_mul_g1,
    schedule_raw_to_payload,
)


def derive_rho_sp1_from_limbs(
    input0: int, input1: int, limb_sets: List[Tuple[int, int, int]]
) -> int:
    data = bytearray(448)
    offset = 0

    data[offset : offset + 32] = input0.to_bytes(32, "little")
    offset += 32
    data[offset : offset + 32] = input1.to_bytes(32, "little")
    offset += 32

    for limbs in limb_sets:
        for limb in limbs:
            data[offset : offset + 16] = limb.to_bytes(16, "little")
            offset += 16

    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % P


def compute_sp1_public_inputs(vkey: int, public_values: bytes) -> Tuple[int, int]:
    digest = hashlib.sha256(public_values).digest()
    masked = bytearray(digest)
    masked[0] &= 0x1F
    return vkey, int.from_bytes(masked, "big")


def parse_proof_bytes(proof_hex: str) -> Tuple[G1Affine, G2Affine, G1Affine]:
    s = proof_hex[2:] if proof_hex.startswith("0x") else proof_hex
    proof_bytes = bytes.fromhex(s)
    if len(proof_bytes) < 4 + 8 * 32:
        raise ValueError("proof hex too short")

    offset = 4

    def read_field() -> int:
        nonlocal offset
        chunk = proof_bytes[offset : offset + 32]
        if len(chunk) != 32:
            raise ValueError("unexpected proof length")
        offset += 32
        return int.from_bytes(chunk, "big")

    a_x = read_field()
    a_y = read_field()
    b_x_c1 = read_field()
    b_x_c0 = read_field()
    b_y_c1 = read_field()
    b_y_c0 = read_field()
    c_x = read_field()
    c_y = read_field()

    a = G1Affine(a_x, a_y)
    b = G2Affine(Fp2(b_x_c0, b_x_c1), Fp2(b_y_c0, b_y_c1))
    c = G1Affine(c_x, c_y)
    return a, b, c


def compute_linear_combination(input0: int, input1: int) -> G1Affine:
    term1 = scalar_mul_g1(SP1_IC1, input0)
    term2 = scalar_mul_g1(SP1_IC2, input1)
    acc = add_g1_jac(g1_affine_to_jac(SP1_IC0), g1_affine_to_jac(term1))
    acc = add_g1_jac(acc, g1_affine_to_jac(term2))
    return jacobian_to_affine_g1(acc)


def compute_witness(
    a: G1Affine, b: G2Affine, c: G1Affine, input0: int, input1: int
) -> Tuple[Fp12, Fp12]:
    l = compute_linear_combination(input0, input1)
    f = miller_loop([a, c, l], [b, SP1_DELTA_NEG, SP1_GAMMA_NEG])
    f_t = f.mul(sp1_t_preimage())

    rng = random.Random(0)
    root_27th = find_root_27th(rng)
    exp = (P**12 - 1) // 3
    w = None
    for s in range(3):
        w_candidate = root_27th.pow(s)
        if f_t.mul(w_candidate).pow(exp).is_one():
            w = w_candidate
            break
    if w is None:
        raise RuntimeError("failed to find cube residue adjustment")

    u = f_t.mul(w)
    h = (P**12 - 1) // R
    r_inv = modinv(R, h)
    u1 = u.pow(r_inv)
    lambda_val = 6 * X + 2 + P - P**2 + P**3
    m = lambda_val // R
    d = math.gcd(m, h)
    m_prime = m // d
    m_inv = modinv(m_prime, h)
    u2 = u1.pow(m_inv)
    c_wit = cube_root(u2, root_27th)

    return c_wit, w


def main() -> None:
    parser = argparse.ArgumentParser(description="SP1 PairingCheck witness generator")
    parser.add_argument("--proof-json", help="SP1 proof JSON (proof/publicValues/vkey)")
    parser.add_argument("--format", choices=["json", "toml"], default="json")
    parser.add_argument("--no-validate", action="store_true")
    parser.add_argument("--print-t-preimage", action="store_true")
    parser.add_argument(
        "--emit-fixed-lines", help="Write fixed line constants noir file"
    )
    parser.add_argument("--output", help="Write output to file")
    args = parser.parse_args()

    outputs: List[str] = []

    if args.print_t_preimage:
        outputs.append("fn sp1_t_preimage() -> Fp12 {")
        outputs.append(emit_fp12_noir(sp1_t_preimage()))
        outputs.append("}")

    if args.proof_json:
        with open(args.proof_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        a, b, c = parse_proof_bytes(data["proof"])
        public_values = bytes.fromhex(
            data["publicValues"][2:]
            if data["publicValues"].startswith("0x")
            else data["publicValues"]
        )
        vkey = int.from_bytes(
            bytes.fromhex(
                data["vkey"][2:] if data["vkey"].startswith("0x") else data["vkey"]
            ),
            "big",
        )
        input0, input1 = compute_sp1_public_inputs(vkey, public_values)
        c_wit, w_wit = compute_witness(a, b, c, input0, input1)
        l = compute_linear_combination(input0, input1)

        b_raw, b_eval, b_witness = compute_b_schedule_with_witness(a, b)
        delta_raw = compute_line_schedule_raw(SP1_DELTA_NEG)
        gamma_raw = compute_line_schedule_raw(SP1_GAMMA_NEG)
        delta_eval = evaluate_schedule_at_p(delta_raw, c)
        gamma_eval = evaluate_schedule_at_p(gamma_raw, l)
        lines_payload = combine_eval_schedules(b_eval, delta_eval, gamma_eval)

        if not args.no_validate:
            f = miller_loop(
                [a, c, compute_linear_combination(input0, input1)],
                [b, SP1_DELTA_NEG, SP1_GAMMA_NEG],
            )
            f_t = f.mul(sp1_t_preimage())
            if not final_exponentiation(f_t).is_one():
                raise SystemExit("final exponentiation check failed")
            if not f_t.mul(w_wit) == c_wit.pow(6 * X + 2 + P - P**2 + P**3):
                raise SystemExit("f_t * w != c^lambda")
            if not w_wit.c1.is_zero():
                raise SystemExit("w not in Fp6")

        payload = {
            "c": fp12_to_limb_list(c_wit),
            "w": fp12_to_limb_list(w_wit),
            "lines": lines_payload,
            "b_lines_raw": schedule_raw_to_payload(b_raw),
            "b_line_witness": line_witness_to_payload(b_witness),
        }

        if args.format == "json":
            outputs.append(json.dumps(payload, indent=2))
        else:
            lines = ["c = ["]
            for row in payload["c"]:
                lines.append(f'  ["{row[0]}", "{row[1]}", "{row[2]}"],')
            lines.append("]")
            lines.append("w = [")
            for row in payload["w"]:
                lines.append(f'  ["{row[0]}", "{row[1]}", "{row[2]}"],')
            lines.append("]")
            outputs.append("\n".join(lines))

        if args.emit_fixed_lines:
            fixed_content = (
                emit_fixed_lines_file(delta_raw, gamma_raw)
                .replace("fixed_delta_lines", "sp1_delta_lines")
                .replace("fixed_gamma_lines", "sp1_gamma_lines")
            )
            with open(args.emit_fixed_lines, "w", encoding="utf-8") as f:
                f.write(fixed_content)

    if not outputs:
        parser.error("no action requested")

    content = "\n\n".join(outputs)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        print(content)


SP1_GAMMA_NEG = G2Affine(
    x=Fp2(
        fp_from_limbs(
            0x4322D4F75EDADD46DEBD5CD992F6ED, 0xDEEF121F1E76426A00665E5C447967, 0x1800
        ),
        fp_from_limbs(
            0xAA493335A9E71297E485B7AEF312C2, 0x9393920D483A7260BFB731FB5D25F1, 0x198E
        ),
    ),
    y=Fp2(
        fp_from_limbs(
            0xAF83285C2DF711EF39C01571827F9D, 0xEFCD05A5323E6DA4D435F3B617CDB3, 0x1D9B
        ),
        fp_from_limbs(
            0x36395DF7BE3B99E673B13A075A65EC, 0xC4A288D1AFB3CBB1AC09187524C7DB, 0x275D
        ),
    ),
)


SP1_DELTA_NEG = G2Affine(
    x=Fp2(
        fp_from_limbs(
            0x3D3B76777A63B327D736BFFB0122ED, 0x41F4BA0C37FE2CAF27354D28E4B8F8, 0x3FF
        ),
        fp_from_limbs(
            0x865E0CC020024521998269845F74E6, 0xCB8DE715675F21F01ECC9B46D236E0, 0x1CC7
        ),
    ),
    y=Fp2(
        fp_from_limbs(
            0x266E474227C6439CA25CA8E1EC1FC2, 0xD3274441670227B4F69A44005B8711, 0x192B
        ),
        fp_from_limbs(
            0xD7F8B2725CD5902A6B20DA7A2938FB, 0x9CD7827E0278E6B60843A4ABC7B111, 0x190
        ),
    ),
)


SP1_IC0 = G1Affine(
    fp_from_limbs(
        0x24779233DB734C451D28B58AA9758E, 0x1E1CAFB0AD8A4EA0A694CD3743EBF5, 0x2609
    ),
    fp_from_limbs(
        0x25489FEFA65A3E782E7BA70B66690E, 0xF50A6B8B11C3CA6FDB2690A124F8CE, 0x9F
    ),
)


SP1_IC1 = G1Affine(
    fp_from_limbs(
        0xED36C6EC878755E537C1C48951FB4C, 0x3FD0FD3DA25D2607C227D090CCA750, 0x61C
    ),
    fp_from_limbs(
        0x5E9A273E6119A212DD09EB51707219, 0x7AE9C2033379DF7B5C65EFF0E10705, 0xFA1
    ),
)


SP1_IC2 = G1Affine(
    fp_from_limbs(
        0xFDEC51A16028DEE020634FD129E71C, 0xB241388A79817FE0E0E2EAD0B2EC4F, 0x4EA
    ),
    fp_from_limbs(
        0xA9E16FCA56B18D5544B0889A65C1F5, 0x6256D21C60D02F0BDBF95CFF83E03E, 0x723
    ),
)


SP1_ALPHA_BETA = Fp12(
    Fp6(
        Fp2(
            fp_from_limbs(
                0xA1ADE8B03E8B987D3578B630DC140D,
                0x9B812ACB2275E21F0CCFD2B5B2C71B,
                0x47C,
            ),
            fp_from_limbs(
                0xAABE2EF7A97706A8942A30D91B604A,
                0xB9BE47B538F0C82106A3FB9B1E13DA,
                0x2E96,
            ),
        ),
        Fp2(
            fp_from_limbs(
                0x99AFC69013773684381D2C74892018,
                0x1F1D74C43656EE464741E6399C7237,
                0xD22,
            ),
            fp_from_limbs(
                0x941C208B4FBC53D65AEDCDA7805CF4,
                0x69ECD427A0CE90DCE160E1DE184905,
                0x1AE0,
            ),
        ),
        Fp2(
            fp_from_limbs(
                0xCF123696B3BA61A91D739D7F8F06D,
                0x3910F5F590D5910FFE4610DE63E7DC,
                0x1176,
            ),
            fp_from_limbs(
                0x997FE53031CCD822922FACDAC67AC5,
                0xDDA5649D0D0C861BD1E1B3ECEDD2DC,
                0xFA3,
            ),
        ),
    ),
    Fp6(
        Fp2(
            fp_from_limbs(
                0x12CD3E2C33863498D5C913E5A8B842,
                0xB627BC5985831858C16686982B1936,
                0xFA5,
            ),
            fp_from_limbs(
                0x51D4BF1954E7C38DC83AD48FE8FE49,
                0xB58BD40A46BDFC4B5B84C4B8254E37,
                0x1650,
            ),
        ),
        Fp2(
            fp_from_limbs(
                0x6CFEEF5F8A6CB7436A6993F2EDE1E4,
                0xF2EFD31E0684176C24C07BCD59DBFD,
                0xA28,
            ),
            fp_from_limbs(
                0x80D70A0AE1724DD8935BBCCA6FE574,
                0x2257E8E26C9335E43A8CCC062DB079,
                0x2BD8,
            ),
        ),
        Fp2(
            fp_from_limbs(
                0x61029C66CAF40CA88899036FA48094,
                0x7A5D05D208EC0D189852BC3FCEF800,
                0x1A62,
            ),
            fp_from_limbs(
                0x38B4D32805C8D7862A2499DD4FCCD3,
                0x11FA3287536B8AB776BC5889266C4,
                0x11C5,
            ),
        ),
    ),
)


SP1_T_PREIMAGE: Fp12 | None = None


def sp1_t_preimage() -> Fp12:
    global SP1_T_PREIMAGE
    if SP1_T_PREIMAGE is None:
        SP1_T_PREIMAGE = compute_t_preimage(SP1_ALPHA_BETA)
    return SP1_T_PREIMAGE


if __name__ == "__main__":
    main()
