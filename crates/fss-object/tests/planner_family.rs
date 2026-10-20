#![forbid(unsafe_code)]
//! FSS-067 property family: archive cost/chunk planner. Each property
//! emits one JSONL verdict line.

use fss_object::planner::{
    ChunkPolicy, MAX_OBJECT_BYTES, MAX_PARTS, MIN_PART_SIZE, PlannerError, plan_chunks,
};

fn emit(property: &str, cases: u64) {
    println!(
        "{{\"family\":\"FSS-067\",\"property\":\"{property}\",\"cases\":{cases},\"verdict\":\"pass\"}}"
    );
}

const MIB: u64 = 1024 * 1024;

fn policy(part_size: u64) -> ChunkPolicy {
    ChunkPolicy { part_size }
}

/// P1 LAYOUT COVERING: chunks tile the object exactly — contiguous,
/// ordered, no gaps or overlaps; every non-final chunk is exactly
/// part_size; the final chunk carries the remainder.
#[test]
fn p1_layout_covers_exactly() -> Result<(), Box<dyn std::error::Error>> {
    let mut cases = 0u64;
    for &(size, part) in &[
        (0u64, 64 * MIB),
        (1, 64 * MIB),
        (64 * MIB, 64 * MIB),
        (64 * MIB + 1, 64 * MIB),
        (200 * MIB + 12345, 64 * MIB),
        (3 * 5 * MIB, 5 * MIB),
    ] {
        let plan = plan_chunks(size, policy(part))?;
        let mut cursor = 0u64;
        for (i, chunk) in plan.chunks.iter().enumerate() {
            assert_eq!(chunk.index, i as u64);
            assert_eq!(chunk.offset, cursor, "contiguous");
            if i + 1 < plan.chunks.len() {
                assert_eq!(chunk.len, part, "full parts are exact");
            }
            cursor += chunk.len;
        }
        assert_eq!(cursor, size, "chunks tile the object exactly");
        assert_eq!(plan.wire_bytes, size, "no padding on the wire");
        cases += 1;
    }
    emit("layout-covering", cases);
    Ok(())
}

/// P2 COST ROW: transfer_work == part count; single-part objects are one
/// work unit; the empty object is one empty part.
#[test]
fn p2_cost_row() -> Result<(), Box<dyn std::error::Error>> {
    let small = plan_chunks(MIB, policy(64 * MIB))?;
    assert_eq!(small.chunks.len(), 1);
    assert_eq!(small.transfer_work, 1);
    assert_eq!(small.wire_bytes, MIB);
    let empty = plan_chunks(0, policy(64 * MIB))?;
    assert_eq!(empty.chunks.len(), 1);
    assert_eq!(empty.chunks[0].len, 0);
    assert_eq!(empty.transfer_work, 1);
    let multi = plan_chunks(3 * 64 * MIB + 7, policy(64 * MIB))?;
    assert_eq!(multi.chunks.len(), 4);
    assert_eq!(multi.transfer_work, 4);
    assert_eq!(multi.chunks[3].len, 7, "remainder carries the tail");
    emit("cost-row", 3);
    Ok(())
}

/// P3 DETERMINISM + DIGEST SENSITIVITY: identical inputs yield identical
/// plans and digests; any input difference changes the digest.
#[test]
fn p3_determinism_and_digest() -> Result<(), Box<dyn std::error::Error>> {
    let a = plan_chunks(129 * MIB, policy(64 * MIB))?;
    let b = plan_chunks(129 * MIB, policy(64 * MIB))?;
    assert_eq!(a, b);
    assert_eq!(a.digest(), b.digest());
    let c = plan_chunks(129 * MIB + 1, policy(64 * MIB))?;
    assert_ne!(a.digest(), c.digest(), "size is digest-bound");
    let d = plan_chunks(129 * MIB, policy(32 * MIB))?;
    assert_ne!(a.digest(), d.digest(), "policy is digest-bound");
    emit("determinism-digest", 4);
    Ok(())
}

/// P4 REFUSALS: oversize objects, sub-floor part sizes, and part-count
/// overflow are typed refusals naming the exact figures.
#[test]
fn p4_refusals() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        plan_chunks(MAX_OBJECT_BYTES + 1, policy(64 * MIB)),
        Err(PlannerError::ObjectTooLarge {
            requested: MAX_OBJECT_BYTES + 1,
            maximum: MAX_OBJECT_BYTES,
        })
    );
    assert_eq!(
        plan_chunks(MIB, policy(MIN_PART_SIZE - 1)),
        Err(PlannerError::PartSizeInvalid {
            requested: MIN_PART_SIZE - 1,
            minimum: MIN_PART_SIZE,
        })
    );
    // Force part-count overflow: minimum part size against an object
    // needing more than MAX_PARTS parts.
    let huge_object = MIN_PART_SIZE * (MAX_PARTS + 1);
    assert!(huge_object <= MAX_OBJECT_BYTES);
    assert_eq!(
        plan_chunks(huge_object, policy(MIN_PART_SIZE)),
        Err(PlannerError::TooManyParts {
            parts: MAX_PARTS + 1,
            maximum: MAX_PARTS,
        })
    );
    emit("refusals", 3);
    Ok(())
}

/// P5 BOUNDARY SWEEP: sizes around each part multiple (part-1, part,
/// part+1) all plan correctly with the right counts.
#[test]
fn p5_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let part = 5 * MIB;
    for &delta in &[-1i64, 0, 1] {
        let size = (2u64 * part).checked_add_signed(delta).ok_or("underflow")?;
        let plan = plan_chunks(size, policy(part))?;
        let expected = match delta {
            -1 => 2, // part + (part-1) remainder
            0 => 2,
            1 => 3, // part + part + 1-byte tail
            _ => unreachable!(),
        };
        assert_eq!(plan.chunks.len(), expected, "size {size}");
    }
    emit("boundary-sweep", 3);
    Ok(())
}
