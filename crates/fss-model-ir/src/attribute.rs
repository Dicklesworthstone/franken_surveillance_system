//! Typed attributes for model operator nodes.

use alloc::collections::BTreeMap;
use core::fmt;

use fss_tensor::{DType, Shape};

use crate::error::ModelIrError;

/// Strongly typed attribute value stored in an operator node.
#[derive(Debug, Clone, PartialEq)]
pub enum AttrValue {
    /// Boolean flag.
    Bool(bool),
    /// Signed 64-bit integer.
    Int(i64),
    /// 64-bit floating point value.
    Float(f64),
    /// UTF-8 string value.
    String(String),
    /// List of signed integers (e.g. axes, strides, kernel dimensions).
    IntList(Vec<i64>),
    /// List of floating point values.
    FloatList(Vec<f64>),
    /// Tensor element data type.
    DType(DType),
    /// Fixed tensor shape.
    Shape(Shape),
}

impl AttrValue {
    /// Extracts attribute as a boolean.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is not a `Bool`.
    pub fn as_bool(&self, node_id: &str, attr_name: &str) -> Result<bool, ModelIrError> {
        match self {
            Self::Bool(b) => Ok(*b),
            _ => Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected boolean attribute".to_string(),
            }),
        }
    }

    /// Extracts attribute as a signed integer.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is not an `Int`.
    pub fn as_int(&self, node_id: &str, attr_name: &str) -> Result<i64, ModelIrError> {
        match self {
            Self::Int(i) => Ok(*i),
            _ => Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected integer attribute".to_string(),
            }),
        }
    }

    /// Extracts attribute as a non-negative `usize`.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is negative or not an `Int`.
    pub fn as_usize(&self, node_id: &str, attr_name: &str) -> Result<usize, ModelIrError> {
        let val = self.as_int(node_id, attr_name)?;
        if val < 0 {
            return Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected non-negative integer for size/dimension".to_string(),
            });
        }
        usize::try_from(val).map_err(|_| ModelIrError::ArithmeticOverflow {
            operation: "attribute integer to usize conversion",
        })
    }

    /// Extracts attribute as a float.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is not a `Float`.
    pub fn as_float(&self, node_id: &str, attr_name: &str) -> Result<f64, ModelIrError> {
        match self {
            Self::Float(f) => Ok(*f),
            _ => Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected float attribute".to_string(),
            }),
        }
    }

    /// Extracts attribute as a string slice.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is not a `String`.
    pub fn as_str<'a>(
        &'a self,
        node_id: &'a str,
        attr_name: &'a str,
    ) -> Result<&'a str, ModelIrError> {
        match self {
            Self::String(s) => Ok(s.as_str()),
            _ => Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected string attribute".to_string(),
            }),
        }
    }

    /// Extracts attribute as an integer list slice.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is not an `IntList`.
    pub fn as_int_list<'a>(
        &'a self,
        node_id: &'a str,
        attr_name: &'a str,
    ) -> Result<&'a [i64], ModelIrError> {
        match self {
            Self::IntList(list) => Ok(list.as_slice()),
            _ => Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected int list attribute".to_string(),
            }),
        }
    }

    /// Extracts attribute as a list of non-negative `usize` values.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if any value is negative or not an `IntList`.
    pub fn as_usize_list(
        &self,
        node_id: &str,
        attr_name: &str,
    ) -> Result<Vec<usize>, ModelIrError> {
        let list = self.as_int_list(node_id, attr_name)?;
        let mut result = Vec::with_capacity(list.len());
        for &v in list {
            if v < 0 {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: node_id.to_string(),
                    attr_name: attr_name.to_string(),
                    reason: "expected non-negative values in index/dimension list".to_string(),
                });
            }
            let u = usize::try_from(v).map_err(|_| ModelIrError::ArithmeticOverflow {
                operation: "list element integer to usize conversion",
            })?;
            result.push(u);
        }
        Ok(result)
    }

    /// Extracts attribute as a float list slice.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is not a `FloatList`.
    pub fn as_float_list<'a>(
        &'a self,
        node_id: &'a str,
        attr_name: &'a str,
    ) -> Result<&'a [f64], ModelIrError> {
        match self {
            Self::FloatList(list) => Ok(list.as_slice()),
            _ => Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected float list attribute".to_string(),
            }),
        }
    }

    /// Extracts attribute as a `DType`.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is not a `DType`.
    pub fn as_dtype(&self, node_id: &str, attr_name: &str) -> Result<DType, ModelIrError> {
        match self {
            Self::DType(dt) => Ok(*dt),
            _ => Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected DType attribute".to_string(),
            }),
        }
    }

    /// Extracts attribute as a reference to `Shape`.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] if value is not a `Shape`.
    pub fn as_shape<'a>(
        &'a self,
        node_id: &'a str,
        attr_name: &'a str,
    ) -> Result<&'a Shape, ModelIrError> {
        match self {
            Self::Shape(s) => Ok(s),
            _ => Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: attr_name.to_string(),
                reason: "expected Shape attribute".to_string(),
            }),
        }
    }
}

impl fmt::Display for AttrValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(b) => write!(f, "Bool({b})"),
            Self::Int(i) => write!(f, "Int({i})"),
            Self::Float(fl) => write!(f, "Float({fl})"),
            Self::String(s) => write!(f, "String({s:?})"),
            Self::IntList(l) => write!(f, "IntList({l:?})"),
            Self::FloatList(l) => write!(f, "FloatList({l:?})"),
            Self::DType(dt) => write!(f, "DType({dt})"),
            Self::Shape(sh) => write!(f, "Shape({sh})"),
        }
    }
}

/// Deterministically sorted attribute map for operator nodes.
pub type AttributeMap = BTreeMap<String, AttrValue>;
