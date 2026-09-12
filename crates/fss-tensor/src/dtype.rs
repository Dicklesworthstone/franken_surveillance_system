//! Data types and typed scalar representations for deterministic tensors.

use core::fmt;
use core::str::FromStr;

use crate::error::TensorError;

/// Fundamental scalar data types supported by `fss-tensor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DType {
    /// 32-bit IEEE 754 single-precision floating point.
    F32,
    /// 64-bit IEEE 754 double-precision floating point.
    F64,
    /// 16-bit IEEE 754 half-precision floating point.
    F16,
    /// 16-bit Brain floating point.
    BF16,
    /// 8-bit signed two's-complement integer.
    I8,
    /// 16-bit signed two's-complement integer.
    I16,
    /// 32-bit signed two's-complement integer.
    I32,
    /// 64-bit signed two's-complement integer.
    I64,
    /// 8-bit unsigned integer.
    U8,
    /// 16-bit unsigned integer.
    U16,
    /// 32-bit unsigned integer.
    U32,
    /// 64-bit unsigned integer.
    U64,
    /// 8-bit boolean (0 = false, 1 = true).
    Bool,
}

impl DType {
    /// Returns the element size in bytes.
    #[must_use]
    pub const fn size_bytes(self) -> usize {
        match self {
            Self::F32 => 4,
            Self::F64 => 8,
            Self::F16 => 2,
            Self::BF16 => 2,
            Self::I8 => 1,
            Self::I16 => 2,
            Self::I32 => 4,
            Self::I64 => 8,
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
            Self::U64 => 8,
            Self::Bool => 1,
        }
    }

    /// Returns the required byte alignment for this data type.
    #[must_use]
    pub const fn alignment(self) -> usize {
        // Primitive alignments match their size in Rust for standard platforms.
        self.size_bytes()
    }

    /// Returns the canonical lower-case name of the data type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::F16 => "f16",
            Self::BF16 => "bf16",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::Bool => "bool",
        }
    }

    /// Returns `true` if this type is a floating-point format.
    #[must_use]
    pub const fn is_floating_point(self) -> bool {
        matches!(self, Self::F32 | Self::F64 | Self::F16 | Self::BF16)
    }

    /// Returns `true` if this type is an integer format.
    #[must_use]
    pub const fn is_integer(self) -> bool {
        matches!(
            self,
            Self::I8
                | Self::I16
                | Self::I32
                | Self::I64
                | Self::U8
                | Self::U16
                | Self::U32
                | Self::U64
        )
    }

    /// Returns `true` if this type is signed.
    #[must_use]
    pub const fn is_signed(self) -> bool {
        matches!(
            self,
            Self::F32
                | Self::F64
                | Self::F16
                | Self::BF16
                | Self::I8
                | Self::I16
                | Self::I32
                | Self::I64
        )
    }

    /// Returns `true` if this type is boolean.
    #[must_use]
    pub const fn is_boolean(self) -> bool {
        matches!(self, Self::Bool)
    }

    /// Parses a data type from its string representation.
    pub fn parse(s: &str) -> Result<Self, TensorError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "f32" | "float32" => Ok(Self::F32),
            "f64" | "float64" => Ok(Self::F64),
            "f16" | "float16" => Ok(Self::F16),
            "bf16" | "bfloat16" => Ok(Self::BF16),
            "i8" | "int8" => Ok(Self::I8),
            "i16" | "int16" => Ok(Self::I16),
            "i32" | "int32" => Ok(Self::I32),
            "i64" | "int64" => Ok(Self::I64),
            "u8" | "uint8" => Ok(Self::U8),
            "u16" | "uint16" => Ok(Self::U16),
            "u32" | "uint32" => Ok(Self::U32),
            "u64" | "uint64" => Ok(Self::U64),
            "bool" | "boolean" => Ok(Self::Bool),
            other => Err(TensorError::InvalidDTypeName {
                name: other.to_string(),
            }),
        }
    }
}

impl fmt::Display for DType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for DType {
    type Err = TensorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A 16-bit IEEE 754 half-precision float represented as raw bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct F16(pub u16);

impl F16 {
    /// Constructs from raw 16-bit unsigned integer representation.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw 16-bit unsigned integer bits.
    #[must_use]
    pub const fn to_bits(self) -> u16 {
        self.0
    }
}

impl fmt::Display for F16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "F16({:#06x})", self.0)
    }
}

/// A 16-bit Brain floating-point format represented as raw bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BF16(pub u16);

impl BF16 {
    /// Constructs from raw 16-bit unsigned integer representation.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw 16-bit unsigned integer bits.
    #[must_use]
    pub const fn to_bits(self) -> u16 {
        self.0
    }
}

impl fmt::Display for BF16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BF16({:#06x})", self.0)
    }
}

/// Trait for Rust types that can be stored and decoded in a `Tensor`.
pub trait TensorScalar: Copy + 'static {
    /// The associated tensor data type.
    const DTYPE: DType;

    /// Encodes the scalar into native-endian bytes.
    fn to_ne_bytes(&self) -> Vec<u8>;

    /// Decodes the scalar from native-endian bytes without unsafe code.
    fn from_ne_bytes(bytes: &[u8]) -> Result<Self, TensorError>;
}

macro_rules! impl_tensor_scalar {
    ($t:ty, $dtype:ident, $size:expr) => {
        impl TensorScalar for $t {
            const DTYPE: DType = DType::$dtype;

            fn to_ne_bytes(&self) -> Vec<u8> {
                <$t>::to_ne_bytes(*self).to_vec()
            }

            fn from_ne_bytes(bytes: &[u8]) -> Result<Self, TensorError> {
                if bytes.len() != $size {
                    return Err(TensorError::StorageLengthMismatch {
                        expected_bytes: $size,
                        actual_bytes: bytes.len(),
                    });
                }
                let mut arr = [0u8; $size];
                arr.copy_from_slice(bytes);
                Ok(<$t>::from_ne_bytes(arr))
            }
        }
    };
}

impl_tensor_scalar!(f32, F32, 4);
impl_tensor_scalar!(f64, F64, 8);
impl_tensor_scalar!(i8, I8, 1);
impl_tensor_scalar!(i16, I16, 2);
impl_tensor_scalar!(i32, I32, 4);
impl_tensor_scalar!(i64, I64, 8);
impl_tensor_scalar!(u8, U8, 1);
impl_tensor_scalar!(u16, U16, 2);
impl_tensor_scalar!(u32, U32, 4);
impl_tensor_scalar!(u64, U64, 8);

impl TensorScalar for F16 {
    const DTYPE: DType = DType::F16;

    fn to_ne_bytes(&self) -> Vec<u8> {
        self.0.to_ne_bytes().to_vec()
    }

    fn from_ne_bytes(bytes: &[u8]) -> Result<Self, TensorError> {
        if bytes.len() != 2 {
            return Err(TensorError::StorageLengthMismatch {
                expected_bytes: 2,
                actual_bytes: bytes.len(),
            });
        }
        let mut arr = [0u8; 2];
        arr.copy_from_slice(bytes);
        Ok(Self(u16::from_ne_bytes(arr)))
    }
}

impl TensorScalar for BF16 {
    const DTYPE: DType = DType::BF16;

    fn to_ne_bytes(&self) -> Vec<u8> {
        self.0.to_ne_bytes().to_vec()
    }

    fn from_ne_bytes(bytes: &[u8]) -> Result<Self, TensorError> {
        if bytes.len() != 2 {
            return Err(TensorError::StorageLengthMismatch {
                expected_bytes: 2,
                actual_bytes: bytes.len(),
            });
        }
        let mut arr = [0u8; 2];
        arr.copy_from_slice(bytes);
        Ok(Self(u16::from_ne_bytes(arr)))
    }
}

impl TensorScalar for bool {
    const DTYPE: DType = DType::Bool;

    fn to_ne_bytes(&self) -> Vec<u8> {
        vec![u8::from(*self)]
    }

    fn from_ne_bytes(bytes: &[u8]) -> Result<Self, TensorError> {
        if bytes.len() != 1 {
            return Err(TensorError::StorageLengthMismatch {
                expected_bytes: 1,
                actual_bytes: bytes.len(),
            });
        }
        match bytes[0] {
            0 => Ok(false),
            1 => Ok(true),
            // Deterministic boolean decoding: reject invalid non-canonical boolean representations
            _ => Err(TensorError::TypeMismatch {
                expected: DType::Bool,
                actual: DType::U8,
            }),
        }
    }
}
