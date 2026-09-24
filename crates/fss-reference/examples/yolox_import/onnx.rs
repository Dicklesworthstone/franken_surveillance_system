//! Bounded, data-only reader for the ONNX protobuf subset an offline import needs.
//!
//! Hand-written protobuf wire decoding (varint, fixed32/64, length-delimited). No schema
//! compiler, reflection, code execution, external data files or sub-graphs. Unknown fields
//! are skipped by wire type; every length is checked against the remaining bytes.

use std::fmt;

/// Hard input ceiling for one model file.
pub const MAX_MODEL_BYTES: usize = 64 * 1024 * 1024;
const MAX_NODES: usize = 4096;
const MAX_INITIALIZERS: usize = 4096;
const MAX_ATTRIBUTES: usize = 64;
const MAX_LIST: usize = 1 << 24;
const MAX_NAME: usize = 256;

/// Typed refusal.
#[derive(Debug)]
pub enum OnnxError {
    /// Truncated or structurally invalid protobuf.
    Malformed(&'static str),
    /// A bound was exceeded.
    Limit(&'static str),
    /// A feature outside this reader's admitted subset (external data, sub-graphs, ...).
    Unsupported(String),
}
impl fmt::Display for OnnxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(what) => write!(f, "malformed ONNX protobuf: {what}"),
            Self::Limit(what) => write!(f, "ONNX bound exceeded: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported ONNX feature: {what}"),
        }
    }
}
impl std::error::Error for OnnxError {}
type Result<T> = std::result::Result<T, OnnxError>;

enum Wire<'a> {
    Varint(u64),
    Fixed64,
    Bytes(&'a [u8]),
    Fixed32(u32),
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0_u64;
        for shift in 0..10 {
            let byte = *self
                .buf
                .get(self.pos)
                .ok_or(OnnxError::Malformed("truncated varint"))?;
            self.pos += 1;
            if shift == 9 && byte > 1 {
                return Err(OnnxError::Malformed("varint overflow"));
            }
            value |= u64::from(byte & 0x7f) << (7 * shift);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(OnnxError::Malformed("varint too long"))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(OnnxError::Malformed("length overflow"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(OnnxError::Malformed("truncated field"))?;
        self.pos = end;
        Ok(slice)
    }
    fn field(&mut self) -> Result<(u64, Wire<'a>)> {
        let key = self.varint()?;
        let number = key >> 3;
        if number == 0 {
            return Err(OnnxError::Malformed("field number zero"));
        }
        let wire = match key & 7 {
            0 => Wire::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Wire::Fixed64
            }
            2 => {
                let len =
                    usize::try_from(self.varint()?).map_err(|_| OnnxError::Limit("length"))?;
                Wire::Bytes(self.take(len)?)
            }
            5 => {
                let b = self.take(4)?;
                Wire::Fixed32(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            }
            _ => {
                return Err(OnnxError::Malformed(
                    "unsupported wire type (groups are not admitted)",
                ));
            }
        };
        Ok((number, wire))
    }
}

fn text(bytes: &[u8]) -> Result<String> {
    if bytes.len() > MAX_NAME {
        return Err(OnnxError::Limit("name length"));
    }
    let s = std::str::from_utf8(bytes).map_err(|_| OnnxError::Malformed("non-UTF-8 name"))?;
    if s.chars().any(char::is_control) {
        return Err(OnnxError::Malformed("control character in name"));
    }
    Ok(s.to_owned())
}
fn int(w: &Wire<'_>) -> Result<i64> {
    match w {
        Wire::Varint(v) => Ok(*v as i64),
        _ => Err(OnnxError::Malformed("expected varint")),
    }
}
fn push_ints(w: &Wire<'_>, out: &mut Vec<i64>) -> Result<()> {
    match w {
        Wire::Varint(v) => out.push(*v as i64),
        Wire::Bytes(b) => {
            let mut r = Reader::new(b);
            while !r.done() {
                out.push(r.varint()? as i64);
            }
        }
        _ => return Err(OnnxError::Malformed("expected integer list")),
    }
    if out.len() > MAX_LIST {
        return Err(OnnxError::Limit("integer list"));
    }
    Ok(())
}
fn push_floats(w: &Wire<'_>, out: &mut Vec<f32>) -> Result<()> {
    match w {
        Wire::Fixed32(v) => out.push(f32::from_bits(*v)),
        Wire::Bytes(b) => {
            if b.len() % 4 != 0 {
                return Err(OnnxError::Malformed("packed float length"));
            }
            out.extend(
                b.as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| f32::from_bits(u32::from_le_bytes(*c))),
            );
        }
        _ => return Err(OnnxError::Malformed("expected float list")),
    }
    if out.len() > MAX_LIST {
        return Err(OnnxError::Limit("float list"));
    }
    Ok(())
}
fn bytes<'a>(w: &Wire<'a>) -> Result<&'a [u8]> {
    match w {
        Wire::Bytes(b) => Ok(b),
        _ => Err(OnnxError::Malformed("expected bytes")),
    }
}

/// ONNX TensorProto.DataType values this reader admits.
pub const DT_FLOAT: i64 = 1;
/// ONNX INT64 element type.
pub const DT_INT64: i64 = 7;

/// A constant tensor (initializer or attribute), decoded to host values.
#[derive(Clone, Debug)]
pub struct Tensor {
    pub name: String,
    pub dims: Vec<i64>,
    pub data_type: i64,
    pub floats: Vec<f32>,
    pub ints: Vec<i64>,
}

impl Tensor {
    fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let mut t = Self {
            name: String::new(),
            dims: Vec::new(),
            data_type: 0,
            floats: Vec::new(),
            ints: Vec::new(),
        };
        let mut raw: Option<&[u8]> = None;
        while !r.done() {
            let (n, w) = r.field()?;
            match n {
                1 => push_ints(&w, &mut t.dims)?,
                2 => t.data_type = int(&w)?,
                4 => push_floats(&w, &mut t.floats)?,
                7 => push_ints(&w, &mut t.ints)?,
                8 => t.name = text(bytes(&w)?)?,
                9 => raw = Some(bytes(&w)?),
                14 => {
                    if int(&w)? != 0 {
                        return Err(OnnxError::Unsupported("external tensor data".into()));
                    }
                }
                13 => return Err(OnnxError::Unsupported("external tensor data".into())),
                5 | 6 | 10 | 11 | 3 => {
                    return Err(OnnxError::Unsupported(format!("tensor data field {n}")));
                }
                _ => {}
            }
        }
        let count = t
            .dims
            .iter()
            .try_fold(1_usize, |acc, d| {
                usize::try_from(*d).ok().and_then(|d| acc.checked_mul(d))
            })
            .ok_or(OnnxError::Malformed("tensor dims"))?;
        if count > MAX_LIST {
            return Err(OnnxError::Limit("tensor elements"));
        }
        if let Some(raw) = raw {
            if !t.floats.is_empty() || !t.ints.is_empty() {
                return Err(OnnxError::Malformed("both raw and typed data"));
            }
            match t.data_type {
                DT_FLOAT => {
                    if raw.len() != count * 4 {
                        return Err(OnnxError::Malformed("raw float length"));
                    }
                    t.floats = raw
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| f32::from_le_bytes(*c))
                        .collect();
                }
                DT_INT64 => {
                    if raw.len() != count * 8 {
                        return Err(OnnxError::Malformed("raw int64 length"));
                    }
                    t.ints = raw
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .map(|c| i64::from_le_bytes(*c))
                        .collect();
                }
                other => {
                    return Err(OnnxError::Unsupported(format!(
                        "tensor element type {other}"
                    )));
                }
            }
        }
        let have = match t.data_type {
            DT_FLOAT => t.floats.len(),
            DT_INT64 => t.ints.len(),
            other => {
                return Err(OnnxError::Unsupported(format!(
                    "tensor element type {other}"
                )));
            }
        };
        if have != count {
            return Err(OnnxError::Malformed("tensor element count"));
        }
        Ok(t)
    }
}

/// One node attribute value.
#[derive(Clone, Debug)]
pub enum AttrValue {
    Int(i64),
    Float(f32),
    Ints(Vec<i64>),
    Floats(Vec<f32>),
    Text(Vec<u8>),
    Tensor(Box<Tensor>),
}

impl AttrValue {
    /// Human-readable value, used in refusal messages.
    pub fn describe(&self) -> String {
        match self {
            Self::Int(v) => v.to_string(),
            Self::Float(v) => v.to_string(),
            Self::Ints(v) => format!("{v:?}"),
            Self::Floats(v) => format!("{v:?}"),
            Self::Text(v) => format!("{:?}", String::from_utf8_lossy(v)),
            Self::Tensor(t) => format!("tensor {:?} dims {:?}", t.name, t.dims),
        }
    }
}

/// One named attribute.
#[derive(Clone, Debug)]
pub struct Attribute {
    pub name: String,
    pub value: AttrValue,
}

impl Attribute {
    fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let (mut name, mut kind) = (String::new(), 0_i64);
        let (mut f, mut i, mut s, mut t) = (None, None, None, None);
        let (mut floats, mut ints) = (Vec::new(), Vec::new());
        while !r.done() {
            let (n, w) = r.field()?;
            match n {
                1 => name = text(bytes(&w)?)?,
                2 => {
                    f = Some(match w {
                        Wire::Fixed32(v) => f32::from_bits(v),
                        _ => return Err(OnnxError::Malformed("float attr")),
                    })
                }
                3 => i = Some(int(&w)?),
                4 => s = Some(bytes(&w)?.to_vec()),
                5 => t = Some(Tensor::parse(bytes(&w)?)?),
                7 => push_floats(&w, &mut floats)?,
                8 => push_ints(&w, &mut ints)?,
                20 => kind = int(&w)?,
                6 | 9 | 10 | 11 | 13 | 14 | 15 => {
                    return Err(OnnxError::Unsupported(format!(
                        "attribute field {n} (graphs/sparse/types)"
                    )));
                }
                _ => {}
            }
        }
        let value = match kind {
            1 => AttrValue::Float(f.ok_or(OnnxError::Malformed("missing float"))?),
            2 => AttrValue::Int(i.ok_or(OnnxError::Malformed("missing int"))?),
            3 => AttrValue::Text(s.ok_or(OnnxError::Malformed("missing string"))?),
            4 => AttrValue::Tensor(Box::new(t.ok_or(OnnxError::Malformed("missing tensor"))?)),
            6 => AttrValue::Floats(floats),
            7 => AttrValue::Ints(ints),
            other => return Err(OnnxError::Unsupported(format!("attribute type {other}"))),
        };
        Ok(Self { name, value })
    }
}

/// One graph node.
#[derive(Clone, Debug)]
pub struct Node {
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub name: String,
    pub op_type: String,
    pub attributes: Vec<Attribute>,
}

impl Node {
    fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let mut node = Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            name: String::new(),
            op_type: String::new(),
            attributes: Vec::new(),
        };
        while !r.done() {
            let (n, w) = r.field()?;
            match n {
                1 => node.inputs.push(text(bytes(&w)?)?),
                2 => node.outputs.push(text(bytes(&w)?)?),
                3 => node.name = text(bytes(&w)?)?,
                4 => node.op_type = text(bytes(&w)?)?,
                5 => {
                    if node.attributes.len() == MAX_ATTRIBUTES {
                        return Err(OnnxError::Limit("attributes"));
                    }
                    node.attributes.push(Attribute::parse(bytes(&w)?)?);
                }
                7 if !bytes(&w)?.is_empty() => {
                    return Err(OnnxError::Unsupported(format!(
                        "operator domain {:?}",
                        String::from_utf8_lossy(bytes(&w)?)
                    )));
                }
                _ => {}
            }
        }
        Ok(node)
    }
    /// Attribute by name.
    pub fn attr(&self, name: &str) -> Option<&AttrValue> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| &a.value)
    }
}

/// Declared graph input/output with static dims (`-1` for a symbolic dim).
#[derive(Clone, Debug)]
pub struct ValueInfo {
    pub name: String,
    pub elem_type: i64,
    pub dims: Vec<i64>,
}

impl ValueInfo {
    fn parse(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf);
        let mut v = Self {
            name: String::new(),
            elem_type: 0,
            dims: Vec::new(),
        };
        while !r.done() {
            let (n, w) = r.field()?;
            match n {
                1 => v.name = text(bytes(&w)?)?,
                2 => {
                    let mut tr = Reader::new(bytes(&w)?);
                    while !tr.done() {
                        let (tn, tw) = tr.field()?;
                        if tn != 1 {
                            continue;
                        } // tensor_type only
                        let mut tt = Reader::new(bytes(&tw)?);
                        while !tt.done() {
                            let (ttn, ttw) = tt.field()?;
                            match ttn {
                                1 => v.elem_type = int(&ttw)?,
                                2 => {
                                    let mut sr = Reader::new(bytes(&ttw)?);
                                    while !sr.done() {
                                        let (sn, sw) = sr.field()?;
                                        if sn != 1 {
                                            continue;
                                        }
                                        let mut dr = Reader::new(bytes(&sw)?);
                                        let mut dim = -1_i64;
                                        while !dr.done() {
                                            let (dn, dw) = dr.field()?;
                                            if dn == 1 {
                                                dim = int(&dw)?;
                                            }
                                        }
                                        v.dims.push(dim);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(v)
    }
}

/// Decoded graph.
#[derive(Clone, Debug)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub initializers: Vec<Tensor>,
    pub inputs: Vec<ValueInfo>,
    pub outputs: Vec<ValueInfo>,
}

/// Decoded model header and graph.
#[derive(Clone, Debug)]
pub struct Model {
    pub ir_version: i64,
    pub producer: String,
    pub producer_version: String,
    pub opsets: Vec<(String, i64)>,
    pub graph: Graph,
}

/// Parse a complete ONNX model file.
pub fn parse_model(buf: &[u8]) -> Result<Model> {
    if buf.len() > MAX_MODEL_BYTES {
        return Err(OnnxError::Limit("model bytes"));
    }
    let mut r = Reader::new(buf);
    let mut model = Model {
        ir_version: 0,
        producer: String::new(),
        producer_version: String::new(),
        opsets: Vec::new(),
        graph: Graph {
            nodes: Vec::new(),
            initializers: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
        },
    };
    let mut graphs = 0;
    while !r.done() {
        let (n, w) = r.field()?;
        match n {
            1 => model.ir_version = int(&w)?,
            2 => model.producer = text(bytes(&w)?)?,
            3 => model.producer_version = text(bytes(&w)?)?,
            7 => {
                graphs += 1;
                model.graph = parse_graph(bytes(&w)?)?;
            }
            8 => {
                let mut or = Reader::new(bytes(&w)?);
                let (mut domain, mut version) = (String::new(), 0);
                while !or.done() {
                    let (on, ow) = or.field()?;
                    match on {
                        1 => domain = text(bytes(&ow)?)?,
                        2 => version = int(&ow)?,
                        _ => {}
                    }
                }
                model.opsets.push((domain, version));
            }
            _ => {}
        }
    }
    if graphs != 1 {
        return Err(OnnxError::Malformed("exactly one graph required"));
    }
    Ok(model)
}

fn parse_graph(buf: &[u8]) -> Result<Graph> {
    let mut r = Reader::new(buf);
    let mut g = Graph {
        nodes: Vec::new(),
        initializers: Vec::new(),
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    while !r.done() {
        let (n, w) = r.field()?;
        match n {
            1 => {
                if g.nodes.len() == MAX_NODES {
                    return Err(OnnxError::Limit("nodes"));
                }
                g.nodes.push(Node::parse(bytes(&w)?)?);
            }
            5 => {
                if g.initializers.len() == MAX_INITIALIZERS {
                    return Err(OnnxError::Limit("initializers"));
                }
                g.initializers.push(Tensor::parse(bytes(&w)?)?);
            }
            11 => g.inputs.push(ValueInfo::parse(bytes(&w)?)?),
            12 => g.outputs.push(ValueInfo::parse(bytes(&w)?)?),
            15 => return Err(OnnxError::Unsupported("sparse initializers".into())),
            _ => {}
        }
    }
    Ok(g)
}
