#![forbid(unsafe_code)]
//! Bounded, row-major F32 matrix tiles with the scalar executor's exact reduction order.
//!
//! The native MatMul contract is rank >= 2, with broadcast batch dimensions. This plan
//! computes batch strides once and visits several independent output cells together. Each
//! cell still starts at positive zero and executes sum += a[k] * b[k] in increasing k
//! order. There is no reassociation, padding multiplication or fused multiply-add.
//! Both operands may be runtime values; attention matrices do not need frozen weights.

use crate::{ExecError, ScalarExecCx};

/// Rows and columns of independent accumulators. Neither is a reduction partition.
pub(super) const MR: usize = 4;
pub(super) const NR: usize = 8;
/// Additional bounded stack payload, reported alongside the executor's heap scratch.
pub(super) const ACCUMULATOR_FLOATS: usize = MR * NR;
/// At most this many reduction terms per cell between cancellation checkpoints.
const REDUCTION_CHECKPOINT: usize = 256;

#[derive(Clone, Debug)]
pub(super) struct PreparedMatMul {
    m: usize,
    k: usize,
    n: usize,
    batch: Vec<usize>,
    a_strides: Vec<usize>,
    b_strides: Vec<usize>,
    a_len: usize,
    b_len: usize,
    output_len: usize,
}

fn overflow() -> ExecError {
    ExecError::ArithmeticOverflow {
        operation: "optimized matmul geometry",
    }
}

fn product(dims: &[usize]) -> Result<usize, ExecError> {
    dims.iter().try_fold(1_usize, |value, &dim| {
        value.checked_mul(dim).ok_or_else(overflow)
    })
}

/// Element strides, right-aligned against the output batch; broadcast axes do not advance.
fn strides(input: &[usize], output: &[usize], matrix: usize) -> Result<Vec<usize>, ExecError> {
    if input.len() > output.len() {
        return Err(super::mismatch("matmul", "OP-MATMUL-001", "batch rank"));
    }
    let mut result = vec![0; output.len()];
    let mut stride = matrix;
    let shift = output.len() - input.len();
    for index in (0..input.len()).rev() {
        let dimension = input[index];
        if dimension != 1 && dimension != output[index + shift] {
            return Err(super::mismatch(
                "matmul",
                "OP-MATMUL-001",
                "batch broadcast",
            ));
        }
        if dimension != 1 {
            result[index + shift] = stride;
        }
        stride = stride.checked_mul(dimension).ok_or_else(overflow)?;
    }
    Ok(result)
}

impl PreparedMatMul {
    /// Empty dimensions keep the established scalar path, including its empty-tensor rules.
    pub(super) fn prepare(
        a: &[usize],
        b: &[usize],
        output: &[usize],
    ) -> Result<Option<Self>, ExecError> {
        if a.len() < 2 || b.len() < 2 || output.len() < 2 {
            return Ok(None);
        }
        if a.contains(&0) || b.contains(&0) || output.contains(&0) {
            return Ok(None);
        }
        let m = a[a.len() - 2];
        let k = a[a.len() - 1];
        let n = b[b.len() - 1];
        if b[b.len() - 2] != k || output[output.len() - 2..] != [m, n] {
            return Err(super::mismatch(
                "matmul",
                "OP-MATMUL-001",
                "matrix dimensions",
            ));
        }
        let batch = output[..output.len() - 2].to_vec();
        Ok(Some(Self {
            m,
            k,
            n,
            a_strides: strides(
                &a[..a.len() - 2],
                &batch,
                m.checked_mul(k).ok_or_else(overflow)?,
            )?,
            b_strides: strides(
                &b[..b.len() - 2],
                &batch,
                k.checked_mul(n).ok_or_else(overflow)?,
            )?,
            batch,
            a_len: product(a)?,
            b_len: product(b)?,
            output_len: product(output)?,
        }))
    }

    pub(super) fn output_len(&self) -> usize {
        self.output_len
    }

    /// Batch ordinal to the two original matrices, with no batch-sized offset table.
    fn bases(&self, mut ordinal: usize) -> (usize, usize) {
        let mut a = 0;
        let mut b = 0;
        for axis in (0..self.batch.len()).rev() {
            let coordinate = ordinal % self.batch[axis];
            ordinal /= self.batch[axis];
            // Checked complete input products at prepare bound every offset here.
            a += coordinate * self.a_strides[axis];
            b += coordinate * self.b_strides[axis];
        }
        (a, b)
    }

    pub(super) fn run(
        &self,
        a: &[f32],
        b: &[f32],
        out: &mut [f32],
        cx: &ScalarExecCx,
    ) -> Result<(), ExecError> {
        self.run_with_checkpoint(a, b, out, &mut |stage| cx.checkpoint(stage))
    }

    fn run_with_checkpoint(
        &self,
        a: &[f32],
        b: &[f32],
        out: &mut [f32],
        check: &mut dyn FnMut(&'static str) -> Result<(), ExecError>,
    ) -> Result<(), ExecError> {
        check("optimized:matmul")?;
        if a.len() != self.a_len || b.len() != self.b_len || out.len() != self.output_len {
            return Err(super::mismatch("matmul", "OP-MATMUL-001", "payload length"));
        }
        let matrix = self.m * self.n;
        for (ordinal, output) in out.chunks_exact_mut(matrix).enumerate() {
            let (base_a, base_b) = self.bases(ordinal);
            let a = &a[base_a..base_a + self.m * self.k];
            let b = &b[base_b..base_b + self.k * self.n];
            for row in (0..self.m).step_by(MR) {
                let rows = (self.m - row).min(MR);
                for column in (0..self.n).step_by(NR) {
                    let columns = (self.n - column).min(NR);
                    let mut sums = [[0.0_f32; NR]; MR];
                    for first_k in (0..self.k).step_by(REDUCTION_CHECKPOINT) {
                        check("optimized:matmul-reduction")?;
                        let end = first_k.saturating_add(REDUCTION_CHECKPOINT).min(self.k);
                        if rows == MR && columns == NR {
                            // Fixed independent lanes let safe compiler vectorization reuse the
                            // contiguous RHS row without changing any cell's reduction order.
                            for ki in first_k..end {
                                let rhs = &b[ki * self.n + column..][..NR];
                                for ri in 0..MR {
                                    let lhs = a[(row + ri) * self.k + ki];
                                    for ci in 0..NR {
                                        sums[ri][ci] += lhs * rhs[ci];
                                    }
                                }
                            }
                        } else {
                            // Only real cells are multiplied: no synthetic zero taps, including
                            // at infinities and NaNs in uneven row/column tails.
                            for ki in first_k..end {
                                let rhs = &b[ki * self.n + column..][..columns];
                                for ri in 0..rows {
                                    let lhs = a[(row + ri) * self.k + ki];
                                    for ci in 0..columns {
                                        sums[ri][ci] += lhs * rhs[ci];
                                    }
                                }
                            }
                        }
                    }
                    for (ri, sum_row) in sums.iter().enumerate().take(rows) {
                        let start = (row + ri) * self.n + column;
                        output[start..start + columns].copy_from_slice(&sum_row[..columns]);
                    }
                }
            }
        }
        check("optimized:matmul-complete")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_single_output_reduction_checks_cancellation_before_finishing() -> Result<(), ExecError>
    {
        let plan = PreparedMatMul::prepare(&[1, 1025], &[1025, 1], &[1, 1])?
            .ok_or_else(|| super::super::mismatch("test", "OP-MATMUL-001", "missing plan"))?;
        let mut checks = 0;
        let mut out = [71.0];
        let result =
            plan.run_with_checkpoint(&vec![1.0; 1025], &vec![2.0; 1025], &mut out, &mut |stage| {
                checks += 1;
                if checks == 4 {
                    Err(ExecError::CancellationRequested { stage })
                } else {
                    Ok(())
                }
            });
        assert!(matches!(
            result,
            Err(ExecError::CancellationRequested { .. })
        ));
        assert_eq!(checks, 4);
        // A tile is copied only after its complete reduction. The graph also withholds all
        // previously completed tiles when any kernel reports cancellation.
        assert_eq!(out, [71.0]);
        Ok(())
    }

    #[test]
    fn invalid_payload_lengths_refuse_before_indexing() -> Result<(), ExecError> {
        let plan = PreparedMatMul::prepare(&[2, 3], &[3, 4], &[2, 4])?
            .ok_or_else(|| super::super::mismatch("test", "OP-MATMUL-001", "missing plan"))?;
        let mut out = [0.0; 8];
        let cx = ScalarExecCx::new();
        assert!(plan.run(&[0.0; 5], &[0.0; 12], &mut out, &cx).is_err());
        assert!(plan.run(&[0.0; 6], &[0.0; 11], &mut out, &cx).is_err());
        assert!(plan.run(&[0.0; 6], &[0.0; 12], &mut out[..7], &cx).is_err());
        Ok(())
    }
}
