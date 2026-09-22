//! Generated-table validation: every CAVLC table emitted by
//! `scripts/generate_cavlc_tables.py` must satisfy the clause 9.2
//! structural properties — prefix-free and Kraft-bounded — from Rust,
//! independently of the Python-side generator assertions.

// Tests fail loudly by design; unwrap/expect/panic are the test idiom.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::cavlc::table_checks::validate_canonical;
use crate::tables::tables;

#[test]
fn all_coeff_token_tables_are_canonical() {
    for (context, table) in tables().coeff_token.iter().enumerate() {
        validate_canonical(table)
            .unwrap_or_else(|err| panic!("coeff_token context {context} invalid: {err}"));
    }
    // Context completeness: 62 entries for the three luma contexts, 14 for
    // chroma DC (tc <= 4).
    assert_eq!(tables().coeff_token[0].entries().len(), 62);
    assert_eq!(tables().coeff_token[3].entries().len(), 14);
}

#[test]
fn all_total_zeros_tables_are_canonical() {
    for (tz_index, table) in tables().total_zeros_4x4.iter().enumerate().skip(1) {
        validate_canonical(table)
            .unwrap_or_else(|err| panic!("total_zeros[{tz_index}] invalid: {err}"));
        // tzVlcIndex k carries total_zeros 0..=16-k.
        assert_eq!(
            table.entries().len(),
            17 - tz_index,
            "tz index {tz_index}: {:?}",
            table.entries()
        );
    }
    for (tz_index, table) in tables().total_zeros_chroma_dc.iter().enumerate().skip(1) {
        validate_canonical(table)
            .unwrap_or_else(|err| panic!("chroma total_zeros[{tz_index}] invalid: {err}"));
        assert_eq!(table.entries().len(), 5 - tz_index);
    }
}

#[test]
fn all_run_before_tables_are_canonical() {
    for (zeros_left, table) in tables().run_before.iter().enumerate().skip(1) {
        validate_canonical(table)
            .unwrap_or_else(|err| panic!("run_before[{zeros_left}] invalid: {err}"));
        let expected = if zeros_left <= 6 { zeros_left + 1 } else { 15 };
        assert_eq!(table.entries().len(), expected);
    }
}

#[test]
fn spot_goldens_match_the_spec() {
    // Known entries from the standard, guarding against value transposition
    // that the structural validators cannot see.
    macro_rules! find {
        ($table:expr, $value:expr) => {
            $table
                .entries()
                .iter()
                .find(|e| e.value == $value)
                .unwrap_or_else(|| panic!("value {} absent", $value))
        };
    }
    // nC in [0,2): tc=1,to=1 -> "01"; tc=1,to=0 -> "000101".
    let tc_to1 = find!(tables().coeff_token[0], 4 + 1);
    assert_eq!((tc_to1.code, tc_to1.len), (0b01, 2));
    let tc_to0 = find!(tables().coeff_token[0], 4);
    assert_eq!((tc_to0.code, tc_to0.len), (0b101, 6));
    // Chroma DC: (tc=1,to=1) -> "1".
    let chroma = find!(tables().coeff_token[3], 4 + 1);
    assert_eq!((chroma.code, chroma.len), (0b1, 1));
    // total_zeros tzVlcIndex=1: tz=0 -> "1".
    let tz0 = tables().total_zeros_4x4[1].entries()[0];
    assert_eq!((tz0.code, tz0.len, tz0.value), (0b1, 1, 0));
    // run_before zerosLeft=1: run 0 -> "1", run 1 -> "0".
    let rb0 = tables().run_before[1].entries()[0];
    assert_eq!((rb0.code, rb0.len, rb0.value), (0b1, 1, 0));
    let rb1 = tables().run_before[1].entries()[1];
    assert_eq!((rb1.code, rb1.len, rb1.value), (0b0, 1, 1));
}
