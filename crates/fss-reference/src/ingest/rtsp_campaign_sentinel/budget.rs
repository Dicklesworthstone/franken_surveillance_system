#![forbid(unsafe_code)]
//! One campaign resource pool. Each native operation receives only the original residual grant.

use super::{Result, RtspCampaignSentinelError as Error};
use crate::ingest::long_sentinel::{LongSentinelLimits, LongSentinelReport, LongSentinelUsage};

pub(super) struct Pool {
    limits: LongSentinelLimits,
    pub usage: LongSentinelUsage,
    pub source_charged: u64,
    pub pixels_charged: u64,
    pub report_bytes: usize,
}
impl Pool {
    pub fn new(limits: LongSentinelLimits) -> Self {
        Self {
            limits,
            usage: LongSentinelUsage::default(),
            source_charged: 0,
            pixels_charged: 0,
            report_bytes: 0,
        }
    }

    pub fn remaining(&self) -> Result<LongSentinelLimits> {
        let mut remaining = self.limits;
        remaining.maximum_source_chunk_bytes = remaining
            .maximum_source_chunk_bytes
            .checked_sub(self.source_charged)
            .ok_or(Error::Limit)?;
        remaining.maximum_pixel_samples = remaining
            .maximum_pixel_samples
            .checked_sub(self.pixels_charged)
            .ok_or(Error::Limit)?;
        remaining.package.jpeg_work_units = remaining
            .package
            .jpeg_work_units
            .checked_sub(self.usage.jpeg_work_units)
            .ok_or(Error::Limit)?;
        remaining.package.detection_work_units = remaining
            .package
            .detection_work_units
            .checked_sub(self.usage.detection_work_units)
            .ok_or(Error::Limit)?;
        remaining.maximum_report_bytes = remaining
            .maximum_report_bytes
            .checked_sub(self.report_bytes)
            .ok_or(Error::Limit)?;
        if remaining.maximum_source_chunk_bytes == 0
            || remaining.maximum_pixel_samples == 0
            || remaining.package.jpeg_work_units == 0
            || remaining.package.detection_work_units == 0
            || remaining.maximum_report_bytes == 0
        {
            return Err(Error::Limit);
        }
        Ok(remaining)
    }

    pub fn charge(
        &mut self,
        report: &LongSentinelReport,
        expected_inferences: usize,
    ) -> Result<()> {
        self.charge_usage(*report.usage(), report.json().len(), expected_inferences)
    }

    fn charge_usage(
        &mut self,
        used: LongSentinelUsage,
        report_bytes: usize,
        expected_inferences: usize,
    ) -> Result<()> {
        if used.inferences != expected_inferences {
            return Err(Error::Invalid(
                "native model count differs from whole-burst allocation",
            ));
        }
        let remaining = self.remaining()?;
        // Preserve both native video admission axes, rather than borrowing spare byte allowance
        // for coded pixels or charging only returned frames while ignoring decode-ahead work.
        let source = used.source_chunk_bytes.max(used.video_encoded_bytes);
        let pixels = used.pixel_samples.max(used.video_coded_luma_capacity);
        if source > remaining.maximum_source_chunk_bytes
            || pixels > remaining.maximum_pixel_samples
            || used.jpeg_work_units > remaining.package.jpeg_work_units
            || used.detection_work_units > remaining.package.detection_work_units
            || report_bytes > remaining.maximum_report_bytes
        {
            return Err(Error::Limit);
        }
        self.source_charged = self
            .source_charged
            .checked_add(source)
            .ok_or(Error::Limit)?;
        self.pixels_charged = self
            .pixels_charged
            .checked_add(pixels)
            .ok_or(Error::Limit)?;
        self.report_bytes = self
            .report_bytes
            .checked_add(report_bytes)
            .ok_or(Error::Limit)?;
        macro_rules! add {
            ($($field:ident),+ $(,)?) => { $(
                self.usage.$field = self.usage.$field.checked_add(used.$field).ok_or(Error::Limit)?;
            )+ };
        }
        add!(
            source_chunk_bytes,
            pixel_samples,
            video_encoded_bytes,
            video_coded_luma_capacity,
            video_decode_work_units,
            jpeg_work_units,
            detection_work_units,
            decoded_frames,
            inferences,
            preprocess_work,
            execution_macs
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_native_grant_cannot_refill_any_campaign_axis() -> Result<()> {
        let mut limits = LongSentinelLimits::default();
        limits.maximum_source_chunk_bytes = 100;
        limits.maximum_pixel_samples = 100;
        limits.package.jpeg_work_units = 100;
        limits.package.detection_work_units = 100;
        limits.maximum_report_bytes = 100;
        let mut pool = Pool::new(limits);
        pool.charge_usage(
            LongSentinelUsage {
                source_chunk_bytes: 20,
                video_encoded_bytes: 30,
                pixel_samples: 4,
                video_coded_luma_capacity: 60,
                jpeg_work_units: 5,
                detection_work_units: 70,
                inferences: 1,
                ..LongSentinelUsage::default()
            },
            40,
            1,
        )?;
        let remaining = pool.remaining()?;
        assert_eq!(remaining.maximum_source_chunk_bytes, 70);
        assert_eq!(remaining.maximum_pixel_samples, 40);
        assert_eq!(remaining.package.jpeg_work_units, 95);
        assert_eq!(remaining.package.detection_work_units, 30);
        assert_eq!(remaining.maximum_report_bytes, 60);
        assert!(matches!(
            pool.charge_usage(
                LongSentinelUsage {
                    source_chunk_bytes: 71,
                    inferences: 1,
                    ..LongSentinelUsage::default()
                },
                1,
                1
            ),
            Err(Error::Limit)
        ));
        assert_eq!(pool.source_charged, 30);
        assert!(matches!(
            pool.charge_usage(
                LongSentinelUsage {
                    video_coded_luma_capacity: 41,
                    inferences: 1,
                    ..LongSentinelUsage::default()
                },
                1,
                1
            ),
            Err(Error::Limit)
        ));
        assert_eq!(pool.usage.inferences, 1);
        Ok(())
    }

    #[test]
    fn exhausted_whole_budget_refuses_another_allocated_recording() -> Result<()> {
        let mut limits = LongSentinelLimits::default();
        limits.package.detection_work_units = 9;
        let mut pool = Pool::new(limits);
        pool.charge_usage(
            LongSentinelUsage {
                detection_work_units: 9,
                inferences: 3,
                ..LongSentinelUsage::default()
            },
            1,
            3,
        )?;
        assert!(matches!(pool.remaining(), Err(Error::Limit)));
        Ok(())
    }
}
