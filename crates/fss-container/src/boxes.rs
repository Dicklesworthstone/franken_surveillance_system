use crate::Mp4Error;

pub(crate) struct Writer {
    pub(crate) data: Vec<u8>,
    limit: usize,
}

impl Writer {
    pub(crate) fn new(limit: usize, capacity: usize) -> Result<Self, Mp4Error> {
        if capacity > limit { return Err(Mp4Error::Limit); }
        let mut data = Vec::new();
        data.try_reserve_exact(capacity).map_err(|_| Mp4Error::Allocation)?;
        Ok(Self { data, limit })
    }

    fn grow(&mut self, count: usize) -> Result<usize, Mp4Error> {
        let end = self.data.len().checked_add(count).ok_or(Mp4Error::Limit)?;
        if end > self.limit { return Err(Mp4Error::Limit); }
        self.data.try_reserve_exact(count).map_err(|_| Mp4Error::Allocation)?;
        Ok(end)
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<(), Mp4Error> {
        self.grow(bytes.len())?;
        self.data.extend_from_slice(bytes);
        Ok(())
    }
    pub(crate) fn zeros(&mut self, count: usize) -> Result<(), Mp4Error> {
        let end = self.grow(count)?;
        self.data.resize(end, 0);
        Ok(())
    }
    pub(crate) fn u16(&mut self, n: u16) -> Result<(), Mp4Error> { self.put(&n.to_be_bytes()) }
    pub(crate) fn u32(&mut self, n: u32) -> Result<(), Mp4Error> { self.put(&n.to_be_bytes()) }
    pub(crate) fn u64(&mut self, n: u64) -> Result<(), Mp4Error> { self.put(&n.to_be_bytes()) }
    pub(crate) fn start(&mut self, tag: &[u8; 4]) -> Result<usize, Mp4Error> {
        let at = self.data.len();
        self.u32(0)?; self.put(tag)?;
        Ok(at)
    }
    pub(crate) fn full(&mut self, tag: &[u8; 4], version_flags: u32) -> Result<usize, Mp4Error> {
        let at = self.start(tag)?;
        self.u32(version_flags)?;
        Ok(at)
    }
    pub(crate) fn end(&mut self, at: usize) -> Result<(), Mp4Error> {
        let size = self.data.len().checked_sub(at).ok_or(Mp4Error::Layout)?;
        let size = u32::try_from(size).map_err(|_| Mp4Error::Limit)?;
        let range = at..at.checked_add(4).ok_or(Mp4Error::Layout)?;
        self.data.get_mut(range).ok_or(Mp4Error::Layout)?.copy_from_slice(&size.to_be_bytes());
        Ok(())
    }
    pub(crate) fn matrix(&mut self) -> Result<(), Mp4Error> {
        for n in [0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000] { self.u32(n)?; }
        Ok(())
    }
}
