#!/usr/bin/env python3
"""Generates crates/fss-codec-h265/src/cabac_tables.rs (H.265 clause 9.3
CABAC tables).

Source: FFmpeg n8.0.1, the sealed laboratory oracle's own transcriptions of
ITU-T H.265 (v4+) Tables 9-5..9-37 (context initValues) and Tables 9-52 /
9-53 (rangeTabLPS, transIdxLps):

- libavcodec/hevc/cabac.c: the CABAC_ELEMS(NAME, NUM_BINS) list, which fixes
  the order and count of the context variables of every context-coded
  syntax element, and init_values[3][HEVC_CONTEXTS] (initValue per context
  for initType 0, 1, 2).
- libavcodec/cabac.c: ff_h264_cabac_tables (the H.264 and H.265 arithmetic
  coders share rangeTabLPS and the state transition tables verbatim).

Usage:
  scripts/generate_h265_cabac_tables.py <libavcodec dir of FFmpeg n8.0.1>

The emitted file holds one `pub const <ELEMENT>: usize` offset per
syntax element (the index of its ctxInc 0 context), INIT_VALUES, and the
engine tables. The Rust unit tests in src/cabac.rs re-check hand-typed
entries of the standard's tables against the output, so a transcription or
parsing slip here fails independently.

Reproducibility: FFmpeg n8.0.1 libavcodec/cabac.c has SHA-256
2071685aebb034f27df24f950526bf5de883797331327a1c8deea5d5b203ff89 and
libavcodec/hevc/cabac.c has SHA-256
f11afb8a77d7ae41c67479b62aa08199b8d718f57a38e6ca3a5d558105169461.
"""
import hashlib
import os
import re
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                   "crates", "fss-codec-h265", "src", "cabac_tables.rs")
EXTENSION_ELEMENTS = {
    "EXPLICIT_RDPCM_FLAG", "EXPLICIT_RDPCM_DIR_FLAG", "LOG2_RES_SCALE_ABS",
    "RES_SCALE_SIGN_FLAG", "CU_CHROMA_QP_OFFSET_FLAG", "CU_CHROMA_QP_OFFSET_IDX",
}
EXPECTED = {
    "cabac.c": "2071685aebb034f27df24f950526bf5de883797331327a1c8deea5d5b203ff89",
    os.path.join("hevc", "cabac.c"):
        "f11afb8a77d7ae41c67479b62aa08199b8d718f57a38e6ca3a5d558105169461",
}


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def initializer(text, name):
    m = re.search(re.escape(name) + r"[^=]*=\s*\{", text)
    assert m, f"missing array {name}"
    depth, i = 1, m.end()
    while depth:
        c = text[i]
        depth += c == "{"
        depth -= c == "}"
        i += 1
    return text[m.end():i - 1]


def ints(body):
    return [int(x) for x in re.findall(r"-?\d+", body)]


def read(src_dir, rel):
    path = os.path.join(src_dir, rel)
    data = open(path, "rb").read()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == EXPECTED[rel], f"{rel}: sha256 {digest} is not FFmpeg n8.0.1"
    return data.decode("utf-8")


def main():
    src_dir = sys.argv[1]
    hevc = read(src_dir, os.path.join("hevc", "cabac.c"))
    cabac = strip_comments(read(src_dir, "cabac.c"))

    # CABAC_ELEMS: ELEM(NAME, NUM_BINS) in context order.
    elems_block = re.search(r"#define CABAC_ELEMS\(ELEM\)(.*?)\n\n", hevc, re.S)
    assert elems_block, "missing CABAC_ELEMS"
    elems = re.findall(r"ELEM\((\w+),\s*(\d+)\)", elems_block.group(1))
    assert len(elems) == 49, len(elems)
    offsets, total = [], 0
    for name, bins in elems:
        offsets.append((name, total, int(bins)))
        total += int(bins)
    # HEVC_CONTEXTS (199) leaves 20 unused trailing slots.
    assert total == 179, total

    body = strip_comments(hevc)
    body = body.replace("CNU", "154")
    init = ints(initializer(body, "init_values"))
    assert len(init) == 3 * total, len(init)
    init_rows = [init[k * total:(k + 1) * total] for k in range(3)]

    tables = [v & 0xFF for v in ints(initializer(cabac, "ff_h264_cabac_tables"))]
    assert len(tables) == 512 + 4 * 2 * 64 + 4 * 64 + 63, len(tables)
    lps = tables[512:512 + 512]
    mlps = tables[1024:1024 + 256]
    range_lps = []
    for state in range(64):
        row = []
        for q in range(4):
            a, b = lps[q * 128 + 2 * state], lps[q * 128 + 2 * state + 1]
            assert a == b
            row.append(a)
        range_lps.append(row)
    trans_lps, trans_mps = [], []
    for p in range(64):
        s = 2 * p
        after_mps, after_lps = mlps[128 + s], mlps[127 - s]
        assert after_mps & 1 == 0
        assert (after_lps & 1) == (1 if p == 0 else 0), (p, after_lps)
        trans_mps.append(after_mps >> 1)
        trans_lps.append(after_lps >> 1)

    def fmt_list(values, per=16):
        return "\n".join("    " + ", ".join(str(v) for v in values[i:i + per]) + ","
                         for i in range(0, len(values), per))

    # Offsets are emitted for the context-coded elements of the Main
    # profile; bypass-only elements (0 contexts) and the range/screen
    # content extension elements keep their slots in INIT_VALUES but get
    # no constant (this decoder refuses those extensions).
    consts = "\n".join(
        f"/// First context of `{name.lower()}` ({bins} context{'s' if bins != 1 else ''}).\n"
        f"pub const {name}: usize = {offset};"
        for name, offset, bins in offsets
        if bins > 0 and name not in EXTENSION_ELEMENTS)
    out = f"""//! CABAC context layout (one offset per context-coded syntax element),
//! context initialisation values and arithmetic-engine tables of ITU-T
//! H.265 clause 9.3.
// GENERATED by scripts/generate_h265_cabac_tables.py from FFmpeg n8.0.1
// libavcodec/hevc/cabac.c and libavcodec/cabac.c (transcriptions of ITU-T
// H.265 Tables 9-5..9-37, 9-52 and 9-53). Do not edit by hand; regenerate.
// Spec entries are re-checked by hand in cabac.rs tests.

/// Number of context variables (all syntax elements, clause 9.3.2.2).
pub const CTX_COUNT: usize = {total};

{consts}

/// initValue per context, indexed by initType 0 (I), 1 and 2.
pub static INIT_VALUES: [[u8; CTX_COUNT]; 3] = [
    [
{fmt_list(init_rows[0])}
    ],
    [
{fmt_list(init_rows[1])}
    ],
    [
{fmt_list(init_rows[2])}
    ],
];

/// rangeTabLps[pStateIdx][qRangeIdx] (Table 9-52).
pub static RANGE_TAB_LPS: [[u8; 4]; 64] = [
{chr(10).join("    [" + ", ".join(str(v) for v in row) + "]," for row in range_lps)}
];

/// transIdxLps[pStateIdx] (Table 9-53).
pub static TRANS_IDX_LPS: [u8; 64] = [
{fmt_list(trans_lps)}
];

/// transIdxMps[pStateIdx] (Table 9-53).
pub static TRANS_IDX_MPS: [u8; 64] = [
{fmt_list(trans_mps)}
];
"""
    with open(OUT, "w") as f:
        f.write(out)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
