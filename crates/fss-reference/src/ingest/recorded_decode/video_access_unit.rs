#![forbid(unsafe_code)]
//! Pure, non-flushing native sample boundary. Output remains local until every NAL and the
//! one-picture contract succeeds. Custody owners must end their range on any returned error.

#[derive(Debug)]
pub(crate) enum UnitError<E> {
    Codec(E),
    Boundary,
    Cancelled,
}

pub(crate) fn h264(
    decoder: &mut fss_codec_h264::Decoder,
    nals: &[&[u8]],
    check: &mut dyn FnMut() -> Result<(), ()>,
) -> Result<Vec<fss_codec_h264::Picture>, UnitError<fss_codec_h264::DecodeError>> {
    let before = decoder.pictures_decoded();
    let mut output = Vec::new();
    for nal in nals {
        check().map_err(|()| UnitError::Cancelled)?;
        let picture = decoder.decode_nal(nal).map_err(UnitError::Codec)?;
        // Stop at the first proven extra picture. A malformed sample must not accumulate an
        // entire recording's output while its owner reserved one picture of decode work.
        if decoder
            .pictures_decoded()
            .checked_sub(before)
            .is_none_or(|count| count > 1)
        {
            return Err(UnitError::Boundary);
        }
        if let Some(picture) = picture {
            output.push(picture);
        }
        while let Some(picture) = decoder.next_output() {
            output.push(picture);
        }
    }
    if decoder.pictures_decoded().checked_sub(before) != Some(1) || decoder.has_incomplete_picture()
    {
        return Err(UnitError::Boundary);
    }
    Ok(output)
}

pub(crate) struct HevcUnit {
    pub output: Vec<fss_codec_h265::Picture>,
    pub skipped_rasl: bool,
}

pub(crate) fn h265(
    decoder: &mut fss_codec_h265::Decoder,
    nals: &[&[u8]],
    check: &mut dyn FnMut() -> Result<(), ()>,
) -> Result<HevcUnit, UnitError<fss_codec_h265::DecodeError>> {
    let before = decoder.pictures_decoded();
    let mut output = Vec::new();
    let mut first_slices = 0_usize;
    let mut rasl_only = true;
    for nal in nals {
        check().map_err(|()| UnitError::Cancelled)?;
        let picture = decoder.decode_nal(nal).map_err(UnitError::Codec)?;
        if decoder
            .pictures_decoded()
            .checked_sub(before)
            .is_none_or(|count| count > 1)
        {
            return Err(UnitError::Boundary);
        }
        if let Some(picture) = picture {
            output.push(picture);
        }
        while let Some(picture) = decoder.next_output() {
            output.push(picture);
        }
        // The first RBSP bit follows the two-byte NAL header; emulation-prevention removal
        // cannot change its position. Inspect it only after successful native validation.
        let kind = nal.first().map(|byte| (byte >> 1) & 0x3f);
        if let Some(kind @ (0..=9 | 16..=21)) = kind {
            rasl_only &= matches!(kind, 8 | 9);
            if nal.get(2).is_some_and(|byte| byte & 0x80 != 0) {
                first_slices += 1;
                if first_slices > 1 {
                    return Err(UnitError::Boundary);
                }
            }
        }
    }
    if first_slices != 1 || decoder.has_incomplete_picture() {
        return Err(UnitError::Boundary);
    }
    let skipped_rasl = match decoder.pictures_decoded().checked_sub(before) {
        Some(1) => false,
        // Exactly one validated RASL first slice, no pending decoded picture and no completed
        // picture can arise only from the codec's actual leading-RASL skip branch.
        Some(0) if rasl_only => true,
        _ => return Err(UnitError::Boundary),
    };
    Ok(HevcUnit {
        output,
        skipped_rasl,
    })
}
