#![forbid(unsafe_code)]
//! Public camera-to-model preprocessing regressions.
use std::error::Error;

use fss_core::Generation;
use fss_reference::preprocess::{ImageBytes, ResizeAspect, ResizeFilter, ResizeOptions};
use fss_reference::{ChannelTransform, ExecBudget, ExecError, PreprocessProgram, ScalarExecCx};
use fss_tensor::{Shape, Tensor};

type TestResult = Result<(), Box<dyn Error>>;

fn options(filter: ResizeFilter, aspect: ResizeAspect) -> ResizeOptions {
    ResizeOptions {
        filter,
        aspect,
        budget: ExecBudget::unlimited(),
    }
}

fn image(bytes: &[u8], h: usize, w: usize, c: usize) -> ImageBytes<'_> {
    ImageBytes {
        bytes,
        height: h,
        width: w,
        channels: c,
        generation: Generation::GENESIS,
    }
}

#[test]
fn nearest_expands_rgb_into_planar_model_input() -> TestResult {
    let program = PreprocessProgram::new(2, 4, ChannelTransform::Rgb, false);
    let result = program.execute_resized_bytes(
        image(&[10, 20, 30, 40, 50, 60], 1, 2, 3),
        options(ResizeFilter::Nearest, ResizeAspect::Stretch),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(result.tensor.shape().dims(), &[1, 3, 2, 4]);
    assert_eq!(
        result.tensor.to_vec::<f32>()?,
        vec![
            10., 10., 40., 40., 10., 10., 40., 40., 20., 20., 50., 50., 20., 20., 50., 50., 30.,
            30., 60., 60., 30., 30., 60., 60.,
        ]
    );
    assert_eq!(result.tensor.generation(), Generation::GENESIS);
    Ok(())
}

#[test]
fn bilinear_uses_half_pixel_centers_and_clamped_edges() -> TestResult {
    let program = PreprocessProgram::new(3, 3, ChannelTransform::LumaOnly, false);
    let result = program.execute_resized_bytes(
        image(&[0, 100, 100, 200], 2, 2, 1),
        options(ResizeFilter::Bilinear, ResizeAspect::Stretch),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        result.tensor.to_vec::<f32>()?,
        vec![0., 50., 100., 50., 100., 150., 100., 150., 200.]
    );
    let downsample = PreprocessProgram::new(1, 1, ChannelTransform::LumaOnly, false)
        .execute_resized_bytes(
            image(&[0, 100, 100, 200], 2, 2, 1),
            options(ResizeFilter::Bilinear, ResizeAspect::Stretch),
            &ScalarExecCx::new(),
        )?;
    assert_eq!(downsample.tensor.to_vec::<f32>()?, vec![100.]);
    Ok(())
}

#[test]
fn identity_resize_preserves_legacy_f32_bits() -> TestResult {
    let rgb: Vec<u8> = (0..36).map(|v| (v * 7) as u8).collect();
    for transform in [ChannelTransform::Rgb, ChannelTransform::LumaOnly] {
        for scale in [false, true] {
            let program = PreprocessProgram::new(3, 4, transform, scale);
            let legacy = program.execute_bytes(&rgb, 3, 4, 3, Generation::GENESIS)?;
            let expected: Vec<u32> = legacy
                .to_vec::<f32>()?
                .iter()
                .map(|v| v.to_bits())
                .collect();
            for filter in [ResizeFilter::Nearest, ResizeFilter::Bilinear] {
                let result = program.execute_resized_bytes(
                    image(&rgb, 3, 4, 3),
                    options(filter, ResizeAspect::Stretch),
                    &ScalarExecCx::new(),
                )?;
                let actual: Vec<u32> = result
                    .tensor
                    .to_vec::<f32>()?
                    .iter()
                    .map(|v| v.to_bits())
                    .collect();
                assert_eq!(actual, expected);
            }
            // The existing v1 encoding and dimension-mismatch behavior stay unchanged.
            assert_eq!(program.canonical_bytes().len(), 18);
            assert!(
                program
                    .execute_bytes(&rgb, 2, 6, 3, Generation::GENESIS)
                    .is_err()
            );
        }
    }
    Ok(())
}

#[test]
fn letterbox_preserves_aspect_and_inverse_detection_geometry() -> TestResult {
    let program = PreprocessProgram::new(5, 5, ChannelTransform::LumaOnly, false);
    let result = program.execute_resized_bytes(
        image(&[200; 8], 2, 4, 1),
        options(ResizeFilter::Nearest, ResizeAspect::Letterbox(7)),
        &ScalarExecCx::new(),
    )?;
    let g = result.geometry;
    assert_eq!((g.image_height, g.image_width, g.top, g.left), (2, 5, 1, 0));
    assert_eq!(
        result.tensor.to_vec::<f32>()?,
        vec![
            7., 7., 7., 7., 7., 200., 200., 200., 200., 200., 200., 200., 200., 200., 200., 7., 7.,
            7., 7., 7., 7., 7., 7., 7., 7.,
        ]
    );
    assert_eq!(g.source_box([0., 1., 5., 3.]), Some([0., 0., 4., 2.]));
    assert_eq!(g.source_box([-10., -10., 10., 10.]), Some([0., 0., 4., 2.]));
    assert_eq!(g.source_box([0., 0., 5., 1.]), None);
    assert_eq!(g.source_box([3., 1., 2., 2.]), None);
    assert_eq!(g.source_box([0., 0., f64::NAN, 2.]), None);
    let tall = program.execute_resized_bytes(
        image(&[200; 8], 4, 2, 1),
        options(ResizeFilter::Nearest, ResizeAspect::Letterbox(7)),
        &ScalarExecCx::new(),
    )?;
    assert_eq!(
        (
            tall.geometry.image_height,
            tall.geometry.image_width,
            tall.geometry.top,
            tall.geometry.left
        ),
        (5, 2, 0, 1)
    );
    Ok(())
}

#[test]
fn replay_digests_bind_pixels_dimensions_generation_and_program() -> TestResult {
    let program = PreprocessProgram::new(2, 2, ChannelTransform::LumaOnly, true);
    let opts = options(ResizeFilter::Nearest, ResizeAspect::Stretch);
    let original = image(&[1, 2, 3, 4], 2, 2, 1);
    let a = program.execute_resized_bytes(original, opts, &ScalarExecCx::new())?;
    let b = program.execute_resized_bytes(original, opts, &ScalarExecCx::new())?;
    assert_eq!(a.input_digest, b.input_digest);
    assert_eq!(a.output_digest, b.output_digest);
    let different =
        program.execute_resized_bytes(image(&[1, 2, 3, 5], 2, 2, 1), opts, &ScalarExecCx::new())?;
    assert_ne!(a.input_digest, different.input_digest);
    assert_ne!(a.output_digest, different.output_digest);
    let next = program.execute_resized_bytes(
        ImageBytes {
            generation: Generation::GENESIS.next()?,
            ..original
        },
        opts,
        &ScalarExecCx::new(),
    )?;
    assert_ne!(a.input_digest, next.input_digest);
    assert_ne!(a.output_digest, next.output_digest);
    let reshaped =
        program.execute_resized_bytes(image(&[1, 2, 3, 4], 1, 4, 1), opts, &ScalarExecCx::new())?;
    assert_ne!(a.input_digest, reshaped.input_digest);
    assert_ne!(
        a.program_digest,
        program.resize_digest(ResizeFilter::Bilinear, ResizeAspect::Stretch)
    );
    assert_ne!(
        a.program_digest,
        program.resize_digest(ResizeFilter::Nearest, ResizeAspect::Letterbox(0))
    );
    assert_ne!(
        program.resize_digest(ResizeFilter::Nearest, ResizeAspect::Letterbox(0)),
        program.resize_digest(ResizeFilter::Nearest, ResizeAspect::Letterbox(1))
    );
    Ok(())
}

#[test]
fn budget_admission_is_inclusive_and_accounts_for_tensor_copy() -> TestResult {
    let program = PreprocessProgram::new(2, 2, ChannelTransform::LumaOnly, false);
    let input = image(&[1, 2, 3, 4], 2, 2, 1);
    let mut opts = options(ResizeFilter::Nearest, ResizeAspect::Stretch);
    let measured = program.execute_resized_bytes(input, opts, &ScalarExecCx::new())?;
    assert_eq!(measured.buffer_bytes, 4 + 2 * 4 * 4);
    opts.budget = ExecBudget::new(measured.work_units, measured.buffer_bytes);
    let exact = program.execute_resized_bytes(input, opts, &ScalarExecCx::new())?;
    assert_eq!(exact.program_digest, measured.program_digest);
    let tensor = Tensor::from_values(Shape::new(vec![2, 2, 1])?, input.bytes, Generation::GENESIS)?;
    assert!(matches!(
        program.execute_resized(&tensor, opts, &ScalarExecCx::new()),
        Err(ExecError::BudgetExceeded { .. })
    ));
    opts.budget.max_bytes += input.bytes.len();
    let copied = program.execute_resized(&tensor, opts, &ScalarExecCx::new())?;
    assert_eq!(copied.output_digest, measured.output_digest);
    assert_eq!(copied.tensor.generation(), tensor.generation());
    opts.budget.max_macs -= 1;
    assert!(matches!(
        program.execute_resized_bytes(input, opts, &ScalarExecCx::new()),
        Err(ExecError::BudgetExceeded { .. })
    ));
    opts.budget = ExecBudget::new(measured.work_units, measured.buffer_bytes - 1);
    assert!(matches!(
        program.execute_resized_bytes(input, opts, &ScalarExecCx::new()),
        Err(ExecError::BudgetExceeded { .. })
    ));
    Ok(())
}

#[test]
fn malformed_and_hostile_inputs_fail_before_pixel_allocation() -> TestResult {
    let program = PreprocessProgram::new(2, 2, ChannelTransform::LumaOnly, false);
    let opts = options(ResizeFilter::Nearest, ResizeAspect::Stretch);
    for bad in [
        image(&[], 0, 1, 1),
        image(&[1], 2, 2, 1),
        image(&[1, 2], 1, 1, 2),
        image(&[], usize::MAX, 2, 1),
    ] {
        assert!(
            program
                .execute_resized_bytes(bad, opts, &ScalarExecCx::new())
                .is_err()
        );
    }
    let huge = PreprocessProgram::new(usize::MAX, usize::MAX, ChannelTransform::Rgb, false);
    assert!(
        huge.execute_resized_bytes(image(&[1, 2, 3], 1, 1, 3), opts, &ScalarExecCx::new())
            .is_err()
    );
    let f32_input = Tensor::from_values(Shape::new(vec![1, 1, 1])?, &[1_f32], Generation::GENESIS)?;
    assert!(matches!(
        program.execute_resized(&f32_input, opts, &ScalarExecCx::new()),
        Err(ExecError::UnsupportedDType { .. })
    ));
    let wrong_rank = Tensor::from_values(Shape::new(vec![1])?, &[1_u8], Generation::GENESIS)?;
    assert!(
        program
            .execute_resized(&wrong_rank, opts, &ScalarExecCx::new())
            .is_err()
    );
    Ok(())
}

#[test]
fn cancellation_returns_no_tensor_and_finalizes_drain() {
    let cx = ScalarExecCx::new();
    cx.request_cancellation();
    let result = PreprocessProgram::new(2, 2, ChannelTransform::LumaOnly, false)
        .execute_resized_bytes(
            image(&[1; 4], 2, 2, 1),
            options(ResizeFilter::Nearest, ResizeAspect::Stretch),
            &cx,
        );
    assert!(matches!(
        result,
        Err(ExecError::CancellationRequested { .. })
    ));
    assert!(cx.is_drain_completed());
}
