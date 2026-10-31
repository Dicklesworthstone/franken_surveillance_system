//! Main-profile tile geometry and raster/tile scan conversion (H.265 6.5.1).

use crate::DecodeError;
use crate::params::{Pps, Sps};

/// Validated column/row boundaries in CTB units. Main and Main Still Picture
/// require at least 256 luma samples per column and 64 per row (Annex A).
pub(crate) fn boundaries(pps: &Pps, sps: &Sps) -> Result<[Vec<u32>; 2], DecodeError> {
    let counts = [pps.tile_columns, pps.tile_rows];
    let sizes = [sps.ctb_width(), sps.ctb_height()];
    let explicit = [&pps.column_widths, &pps.row_heights];
    if counts[0] == 0
        || counts[1] == 0
        || counts[0] > 40
        || counts[1] > 44
        || counts == [1, 1]
        || pps.entropy_coding_sync
    {
        return Err(DecodeError::Malformed);
    }
    let mut result: [Vec<u32>; 2] = [Vec::new(), Vec::new()];
    for axis in 0..2 {
        let count = counts[axis];
        if count > sizes[axis]
            || (!pps.uniform_tile_spacing && explicit[axis].len() != count as usize - 1)
        {
            return Err(DecodeError::Malformed);
        }
        let values = &mut result[axis];
        values
            .try_reserve_exact(count as usize + 1)
            .map_err(|_| DecodeError::Limit)?;
        values.push(0);
        for index in 1..count {
            let next = if pps.uniform_tile_spacing {
                index * sizes[axis] / count
            } else {
                values[index as usize - 1]
                    .checked_add(explicit[axis][index as usize - 1])
                    .ok_or(DecodeError::Malformed)?
            };
            if next <= values[index as usize - 1] || next >= sizes[axis] {
                return Err(DecodeError::Malformed);
            }
            values.push(next);
        }
        values.push(sizes[axis]);
        for pair in values.windows(2) {
            // Clause 6.5.1 defines these sample widths from CTB spans,
            // including padding in the final, partially occupied CTB.
            if (pair[1] - pair[0]) << sps.ctb_log2 < [256, 64][axis] {
                return Err(DecodeError::Malformed);
            }
        }
    }
    Ok(result)
}

/// Bounded header-only conversion, including skipped RASL pictures that allocate
/// neither a decoded surface nor the full CTB maps.
pub(crate) fn scan_address(pps: &Pps, sps: &Sps, raster: u32) -> Result<u32, DecodeError> {
    if raster >= sps.ctb_width() * sps.ctb_height() {
        return Err(DecodeError::Malformed);
    }
    if !pps.tiles_enabled {
        return Ok(raster);
    }
    let [columns, rows] = boundaries(pps, sps)?;
    let (x, y) = (raster % sps.ctb_width(), raster / sps.ctb_width());
    let column = columns
        .windows(2)
        .find(|v| x >= v[0] && x < v[1])
        .ok_or(DecodeError::Malformed)?;
    let row = rows
        .windows(2)
        .find(|v| y >= v[0] && y < v[1])
        .ok_or(DecodeError::Malformed)?;
    Ok(row[0] * sps.ctb_width()
        + column[0] * (row[1] - row[0])
        + (y - row[0]) * (column[1] - column[0])
        + x
        - column[0])
}

/// Allocated only for tiled pictures, after SPS limits have been validated.
/// Three bounded CTB maps cost ten bytes per CTB, plus two tile-bound arrays.
pub(crate) struct TileLayout {
    raster_to_scan: Vec<u32>,
    scan_to_raster: Vec<u32>,
    tile_ids: Vec<u16>,
    starts: Vec<u32>,
    ends: Vec<u32>,
    ctb_width: usize,
    ctb_log2: u32,
    pub loop_filter_across: bool,
}

impl TileLayout {
    pub fn new(pps: &Pps, sps: &Sps) -> Result<Option<Self>, DecodeError> {
        if !pps.tiles_enabled {
            return Ok(None);
        }
        let [columns, rows] = boundaries(pps, sps)?;
        let total = (sps.ctb_width() * sps.ctb_height()) as usize;
        let allocate = || -> Result<Vec<u32>, DecodeError> {
            let mut map = Vec::new();
            map.try_reserve_exact(total)
                .map_err(|_| DecodeError::Limit)?;
            map.resize(total, 0);
            Ok(map)
        };
        let mut raster_to_scan = allocate()?;
        let mut scan_to_raster = allocate()?;
        let mut tile_ids = Vec::new();
        tile_ids
            .try_reserve_exact(total)
            .map_err(|_| DecodeError::Limit)?;
        tile_ids.resize(total, 0);
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        let count = (pps.tile_columns * pps.tile_rows) as usize;
        starts
            .try_reserve_exact(count)
            .map_err(|_| DecodeError::Limit)?;
        ends.try_reserve_exact(count)
            .map_err(|_| DecodeError::Limit)?;
        let mut scan = 0usize;
        for row in rows.windows(2) {
            for column in columns.windows(2) {
                let id = starts.len() as u16;
                starts.push(scan as u32);
                for y in row[0]..row[1] {
                    for x in column[0]..column[1] {
                        let raster = y * sps.ctb_width() + x;
                        raster_to_scan[raster as usize] = scan as u32;
                        scan_to_raster[scan] = raster;
                        tile_ids[raster as usize] = id;
                        scan += 1;
                    }
                }
                ends.push(scan as u32);
            }
        }
        Ok(Some(Self {
            raster_to_scan,
            scan_to_raster,
            tile_ids,
            starts,
            ends,
            ctb_width: sps.ctb_width() as usize,
            ctb_log2: sps.ctb_log2,
            loop_filter_across: pps.loop_filter_across_tiles,
        }))
    }

    pub fn scan(&self, raster: usize) -> usize {
        self.raster_to_scan[raster] as usize
    }

    pub fn raster(&self, scan: usize) -> usize {
        self.scan_to_raster[scan] as usize
    }

    pub fn id(&self, raster: usize) -> u16 {
        self.tile_ids[raster]
    }

    pub fn is_start(&self, raster: usize) -> bool {
        self.raster_to_scan[raster] == self.starts[usize::from(self.id(raster))]
    }

    pub fn end(&self, raster: usize) -> usize {
        self.ends[usize::from(self.id(raster))] as usize
    }

    pub fn same_pixels(&self, x: usize, y: usize, nx: usize, ny: usize) -> bool {
        let address = |x, y| (y >> self.ctb_log2) * self.ctb_width + (x >> self.ctb_log2);
        self.id(address(x, y)) == self.id(address(nx, ny))
    }
}
