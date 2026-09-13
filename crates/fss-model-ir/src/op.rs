//! Closed, versioned operator set with stable operator identifiers and pinned attribute schemas.

use core::fmt;

use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};

use crate::error::ModelIrError;

/// Domain tag for canonical operator table freeze digest computation.
pub const OPERATOR_TABLE_DIGEST_DOMAIN: &[u8] = b"fss.model_ir.operator_table.v1\0";

/// Pinned canonical freeze digest covering all 22 operators and their attribute schemas.
///
/// Any modification to operator IDs, names, or attribute schemas alters this digest
/// and requires an explicit IR generation bump.
pub const OPERATOR_TABLE_FREEZE_DIGEST: &str =
    "sha256:ea84259adbccf747c847b53629fe9176dea0f6cc1874bd5379066d32d30211be";

/// Stable baseline operator identifiers for Model IR v1.
///
/// Identifiers must remain immutable, monotonic, and match normative registrations.
pub const OPERATOR_BASELINE_IDS: &[&str] = &[
    "OP-ADD-001",
    "OP-SUB-001",
    "OP-MUL-001",
    "OP-DIV-001",
    "OP-RELU-001",
    "OP-GELU-001",
    "OP-SILU-001",
    "OP-SIGMOID-001",
    "OP-TANH-001",
    "OP-MATMUL-001",
    "OP-RESHAPE-001",
    "OP-TRANSPOSE-001",
    "OP-SQUEEZE-001",
    "OP-UNSQUEEZE-001",
    "OP-CONCAT-001",
    "OP-SLICE-001",
    "OP-LAYERNORM-001",
    "OP-RMSNORM-001",
    "OP-SOFTMAX-001",
    "OP-CONV2D-001",
    "OP-MAXPOOL2D-001",
    "OP-EMBEDDING-001",
];

/// Tombstoned operator identifiers that must never be resurrected or reused.
pub const OPERATOR_TOMBSTONES: &[&str] = &[];

/// Strongly typed attribute classification for closed schema validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeType {
    /// Boolean attribute.
    Bool,
    /// 64-bit signed integer attribute.
    Int,
    /// 64-bit floating point attribute.
    Float,
    /// String attribute.
    String,
    /// List of 64-bit signed integers.
    IntList,
    /// List of 64-bit floating point values.
    FloatList,
    /// Tensor element data type attribute.
    DType,
    /// Tensor shape attribute.
    Shape,
}

impl AttributeType {
    /// Numerical type tag for canonical serialization.
    #[must_use]
    pub const fn type_tag(&self) -> u8 {
        match self {
            Self::Bool => 1,
            Self::Int => 2,
            Self::Float => 3,
            Self::String => 4,
            Self::IntList => 5,
            Self::FloatList => 6,
            Self::DType => 7,
            Self::Shape => 8,
        }
    }
}

/// Normative specification for a single admitted operator attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeSpec {
    /// Canonical attribute name.
    pub name: &'static str,
    /// Expected attribute type.
    pub attr_type: AttributeType,
    /// Whether this attribute is required (true) or optional with default (false).
    pub required: bool,
    /// Canonical default representation if optional.
    pub default_value: Option<&'static str>,
}

impl AttributeSpec {
    /// Validates that an attribute value matches this schema specification.
    ///
    /// # Errors
    /// Returns [`ModelIrError::InvalidAttribute`] on type mismatch.
    pub fn validate_type(
        &self,
        node_id: &str,
        val: &crate::attribute::AttrValue,
    ) -> Result<(), ModelIrError> {
        let matches = match (self.attr_type, val) {
            (AttributeType::Bool, crate::attribute::AttrValue::Bool(_)) => true,
            (AttributeType::Int, crate::attribute::AttrValue::Int(_)) => true,
            (AttributeType::Float, crate::attribute::AttrValue::Float(_)) => true,
            (AttributeType::String, crate::attribute::AttrValue::String(_)) => true,
            (AttributeType::IntList, crate::attribute::AttrValue::IntList(_)) => true,
            (AttributeType::FloatList, crate::attribute::AttrValue::FloatList(_)) => true,
            (AttributeType::DType, crate::attribute::AttrValue::DType(_)) => true,
            (AttributeType::Shape, crate::attribute::AttrValue::Shape(_)) => true,
            // Allow Reshape / LayerNorm normalized_shape to accept either IntList or Shape
            (AttributeType::IntList, crate::attribute::AttrValue::Shape(_))
                if self.name == "shape" || self.name == "normalized_shape" =>
            {
                true
            }
            _ => false,
        };
        if !matches {
            return Err(ModelIrError::InvalidAttribute {
                node_id: node_id.to_string(),
                attr_name: self.name.to_string(),
                reason: format!(
                    "attribute '{}' expected {:?}, got {:?}",
                    self.name, self.attr_type, val
                ),
            });
        }
        Ok(())
    }
}

/// Normative metadata specification for a closed first-party model operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorSpec {
    /// Associated enumeration opcode.
    pub opcode: OpCode,
    /// Normative stable identifier (`OP-...-001`).
    pub stable_id: &'static str,
    /// Canonical human-readable name.
    pub name: &'static str,
    /// Minimum input port count.
    pub min_inputs: usize,
    /// Maximum input port count.
    pub max_inputs: usize,
    /// Inferred output port count.
    pub output_count: usize,
    /// Strictly admitted attribute specifications (empty slice means operator rejects all attributes).
    pub allowed_attributes: &'static [AttributeSpec],
}

impl OperatorSpec {
    /// Returns the attribute specification for `attr_name`, or `None` if not admitted.
    #[must_use]
    pub fn get_attribute_spec(&self, attr_name: &str) -> Option<&'static AttributeSpec> {
        self.allowed_attributes
            .iter()
            .find(|attr| attr.name == attr_name)
    }

    /// Returns `true` if `attr_name` is admitted in this operator's schema.
    #[must_use]
    pub fn is_attribute_allowed(&self, attr_name: &str) -> bool {
        self.get_attribute_spec(attr_name).is_some()
    }
}

/// Normative table of all 22 operators in Model IR v1 with their admitted attribute schemas.
pub const OPERATOR_SPECS: &[OperatorSpec] = &[
    OperatorSpec {
        opcode: OpCode::Add,
        stable_id: "OP-ADD-001",
        name: "add",
        min_inputs: 2,
        max_inputs: 2,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Sub,
        stable_id: "OP-SUB-001",
        name: "sub",
        min_inputs: 2,
        max_inputs: 2,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Mul,
        stable_id: "OP-MUL-001",
        name: "mul",
        min_inputs: 2,
        max_inputs: 2,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Div,
        stable_id: "OP-DIV-001",
        name: "div",
        min_inputs: 2,
        max_inputs: 2,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Relu,
        stable_id: "OP-RELU-001",
        name: "relu",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Gelu,
        stable_id: "OP-GELU-001",
        name: "gelu",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[AttributeSpec {
            name: "approximate",
            attr_type: AttributeType::String,
            required: false,
            default_value: Some("none"),
        }],
    },
    OperatorSpec {
        opcode: OpCode::Silu,
        stable_id: "OP-SILU-001",
        name: "silu",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Sigmoid,
        stable_id: "OP-SIGMOID-001",
        name: "sigmoid",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Tanh,
        stable_id: "OP-TANH-001",
        name: "tanh",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::MatMul,
        stable_id: "OP-MATMUL-001",
        name: "matmul",
        min_inputs: 2,
        max_inputs: 2,
        output_count: 1,
        allowed_attributes: &[],
    },
    OperatorSpec {
        opcode: OpCode::Reshape,
        stable_id: "OP-RESHAPE-001",
        name: "reshape",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[
            AttributeSpec {
                name: "allowzero",
                attr_type: AttributeType::Bool,
                required: false,
                default_value: Some("false"),
            },
            AttributeSpec {
                name: "shape",
                attr_type: AttributeType::IntList,
                required: true,
                default_value: None,
            },
        ],
    },
    OperatorSpec {
        opcode: OpCode::Transpose,
        stable_id: "OP-TRANSPOSE-001",
        name: "transpose",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[AttributeSpec {
            name: "permutation",
            attr_type: AttributeType::IntList,
            required: false,
            default_value: Some("reverse"),
        }],
    },
    OperatorSpec {
        opcode: OpCode::Squeeze,
        stable_id: "OP-SQUEEZE-001",
        name: "squeeze",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[AttributeSpec {
            name: "axes",
            attr_type: AttributeType::IntList,
            required: false,
            default_value: Some("all_ones"),
        }],
    },
    OperatorSpec {
        opcode: OpCode::Unsqueeze,
        stable_id: "OP-UNSQUEEZE-001",
        name: "unsqueeze",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[AttributeSpec {
            name: "axes",
            attr_type: AttributeType::IntList,
            required: true,
            default_value: None,
        }],
    },
    OperatorSpec {
        opcode: OpCode::Concat,
        stable_id: "OP-CONCAT-001",
        name: "concat",
        min_inputs: 1,
        max_inputs: usize::MAX,
        output_count: 1,
        allowed_attributes: &[AttributeSpec {
            name: "axis",
            attr_type: AttributeType::Int,
            required: false,
            default_value: Some("0"),
        }],
    },
    OperatorSpec {
        opcode: OpCode::Slice,
        stable_id: "OP-SLICE-001",
        name: "slice",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[
            AttributeSpec {
                name: "axes",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: Some("0..N"),
            },
            AttributeSpec {
                name: "ends",
                attr_type: AttributeType::IntList,
                required: true,
                default_value: None,
            },
            AttributeSpec {
                name: "starts",
                attr_type: AttributeType::IntList,
                required: true,
                default_value: None,
            },
            AttributeSpec {
                name: "steps",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: Some("1..1"),
            },
        ],
    },
    OperatorSpec {
        opcode: OpCode::LayerNorm,
        stable_id: "OP-LAYERNORM-001",
        name: "layer_norm",
        min_inputs: 1,
        max_inputs: 3,
        output_count: 1,
        allowed_attributes: &[
            AttributeSpec {
                name: "bias",
                attr_type: AttributeType::Bool,
                required: false,
                default_value: Some("true"),
            },
            AttributeSpec {
                name: "elementwise_affine",
                attr_type: AttributeType::Bool,
                required: false,
                default_value: Some("true"),
            },
            AttributeSpec {
                name: "epsilon",
                attr_type: AttributeType::Float,
                required: false,
                default_value: Some("1e-5"),
            },
            AttributeSpec {
                name: "normalized_shape",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: None,
            },
            AttributeSpec {
                name: "scale",
                attr_type: AttributeType::Bool,
                required: false,
                default_value: Some("true"),
            },
        ],
    },
    OperatorSpec {
        opcode: OpCode::RMSNorm,
        stable_id: "OP-RMSNORM-001",
        name: "rms_norm",
        min_inputs: 1,
        max_inputs: 2,
        output_count: 1,
        allowed_attributes: &[
            AttributeSpec {
                name: "elementwise_affine",
                attr_type: AttributeType::Bool,
                required: false,
                default_value: Some("true"),
            },
            AttributeSpec {
                name: "epsilon",
                attr_type: AttributeType::Float,
                required: false,
                default_value: Some("1e-5"),
            },
            AttributeSpec {
                name: "normalized_shape",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: None,
            },
            AttributeSpec {
                name: "scale",
                attr_type: AttributeType::Bool,
                required: false,
                default_value: Some("true"),
            },
        ],
    },
    OperatorSpec {
        opcode: OpCode::Softmax,
        stable_id: "OP-SOFTMAX-001",
        name: "softmax",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[AttributeSpec {
            name: "axis",
            attr_type: AttributeType::Int,
            required: false,
            default_value: Some("-1"),
        }],
    },
    OperatorSpec {
        opcode: OpCode::Conv2d,
        stable_id: "OP-CONV2D-001",
        name: "conv2d",
        min_inputs: 2,
        max_inputs: 3,
        output_count: 1,
        allowed_attributes: &[
            AttributeSpec {
                name: "dilations",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: Some("[1, 1]"),
            },
            AttributeSpec {
                name: "groups",
                attr_type: AttributeType::Int,
                required: false,
                default_value: Some("1"),
            },
            AttributeSpec {
                name: "padding",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: Some("[0, 0, 0, 0]"),
            },
            AttributeSpec {
                name: "strides",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: Some("[1, 1]"),
            },
        ],
    },
    OperatorSpec {
        opcode: OpCode::MaxPool2d,
        stable_id: "OP-MAXPOOL2D-001",
        name: "max_pool2d",
        min_inputs: 1,
        max_inputs: 1,
        output_count: 1,
        allowed_attributes: &[
            AttributeSpec {
                name: "ceil_mode",
                attr_type: AttributeType::Bool,
                required: false,
                default_value: Some("false"),
            },
            AttributeSpec {
                name: "kernel_size",
                attr_type: AttributeType::IntList,
                required: true,
                default_value: None,
            },
            AttributeSpec {
                name: "padding",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: Some("[0, 0, 0, 0]"),
            },
            AttributeSpec {
                name: "strides",
                attr_type: AttributeType::IntList,
                required: false,
                default_value: Some("[1, 1]"),
            },
        ],
    },
    OperatorSpec {
        opcode: OpCode::Embedding,
        stable_id: "OP-EMBEDDING-001",
        name: "embedding",
        min_inputs: 2,
        max_inputs: 2,
        output_count: 1,
        allowed_attributes: &[
            AttributeSpec {
                name: "dtype",
                attr_type: AttributeType::DType,
                required: false,
                default_value: None,
            },
            AttributeSpec {
                name: "embedding_dim",
                attr_type: AttributeType::Int,
                required: false,
                default_value: None,
            },
            AttributeSpec {
                name: "num_embeddings",
                attr_type: AttributeType::Int,
                required: false,
                default_value: None,
            },
            AttributeSpec {
                name: "padding_idx",
                attr_type: AttributeType::Int,
                required: false,
                default_value: None,
            },
        ],
    },
];

/// Stable, closed set of first-party model operators for Model IR v1.
///
/// Every operator has a canonical `OP-...-001` identifier that is never renumbered.
/// The set is closed; unadmitted operators must be rejected by the graph validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OpCode {
    /// Elementwise addition: A + B (OP-ADD-001).
    Add,
    /// Elementwise subtraction: A - B (OP-SUB-001).
    Sub,
    /// Elementwise multiplication: A * B (OP-MUL-001).
    Mul,
    /// Elementwise division: A / B (OP-DIV-001).
    Div,
    /// Rectified linear unit activation (OP-RELU-001).
    Relu,
    /// Gaussian error linear unit activation (OP-GELU-001).
    Gelu,
    /// Sigmoid linear unit / Swish activation (OP-SILU-001).
    Silu,
    /// Logistic sigmoid activation (OP-SIGMOID-001).
    Sigmoid,
    /// Hyperbolic tangent activation (OP-TANH-001).
    Tanh,
    /// Matrix multiplication / batched GEMM (OP-MATMUL-001).
    MatMul,
    /// Tensor view reshaping with element-count preservation (OP-RESHAPE-001).
    Reshape,
    /// Axis permutation (OP-TRANSPOSE-001).
    Transpose,
    /// Removal of dimensions of size 1 (OP-SQUEEZE-001).
    Squeeze,
    /// Insertion of dimensions of size 1 (OP-UNSQUEEZE-001).
    Unsqueeze,
    /// Concatenation of tensors along a specified axis (OP-CONCAT-001).
    Concat,
    /// Sub-tensor slicing along specified axes (OP-SLICE-001).
    Slice,
    /// Layer normalization with mean and variance scaling (OP-LAYERNORM-001).
    LayerNorm,
    /// Root mean square normalization (OP-RMSNORM-001).
    RMSNorm,
    /// Softmax normalized exponential over a specified axis (OP-SOFTMAX-001).
    Softmax,
    /// 2D spatial convolution (OP-CONV2D-001).
    Conv2d,
    /// 2D spatial maximum pooling (OP-MAXPOOL2D-001).
    MaxPool2d,
    /// Lookup table embedding (OP-EMBEDDING-001).
    Embedding,
}

impl OpCode {
    /// Returns the normative specification record for this operator.
    #[must_use]
    pub const fn spec(&self) -> &'static OperatorSpec {
        let idx = *self as usize;
        &OPERATOR_SPECS[idx]
    }

    /// Returns the stable, normative identifier for this operator.
    #[must_use]
    pub const fn stable_id(&self) -> &'static str {
        self.spec().stable_id
    }

    /// Returns the canonical human-readable name of this operator.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.spec().name
    }

    /// Returns the strictly admitted attribute specifications for this operator.
    #[must_use]
    pub const fn allowed_attributes(&self) -> &'static [AttributeSpec] {
        self.spec().allowed_attributes
    }

    /// Returns the attribute specification for `attr_name`, or `None` if not admitted.
    #[must_use]
    pub fn get_attribute_spec(&self, attr_name: &str) -> Option<&'static AttributeSpec> {
        self.spec().get_attribute_spec(attr_name)
    }

    /// Returns `true` if `attr_name` is admitted in this operator's schema.
    #[must_use]
    pub fn is_attribute_allowed(&self, attr_name: &str) -> bool {
        self.spec().is_attribute_allowed(attr_name)
    }

    /// Resolves an `OpCode` from its stable `OP-...-001` identifier.
    ///
    /// # Errors
    /// Returns [`ModelIrError::UnknownOperator`] if the identifier is not recognized.
    pub fn from_stable_id(id: &str) -> Result<Self, ModelIrError> {
        for spec in OPERATOR_SPECS {
            if spec.stable_id == id {
                return Ok(spec.opcode);
            }
        }
        Err(ModelIrError::UnknownOperator {
            op_id: id.to_string(),
        })
    }

    /// Resolves an `OpCode` from its canonical name.
    ///
    /// # Errors
    /// Returns [`ModelIrError::UnknownOperator`] if the name is not recognized.
    pub fn from_name(name: &str) -> Result<Self, ModelIrError> {
        for spec in OPERATOR_SPECS {
            if spec.name == name {
                return Ok(spec.opcode);
            }
        }
        Err(ModelIrError::UnknownOperator {
            op_id: name.to_string(),
        })
    }

    /// Returns an immutable slice of all closed operators admitted in Model IR v1.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Add,
            Self::Sub,
            Self::Mul,
            Self::Div,
            Self::Relu,
            Self::Gelu,
            Self::Silu,
            Self::Sigmoid,
            Self::Tanh,
            Self::MatMul,
            Self::Reshape,
            Self::Transpose,
            Self::Squeeze,
            Self::Unsqueeze,
            Self::Concat,
            Self::Slice,
            Self::LayerNorm,
            Self::RMSNorm,
            Self::Softmax,
            Self::Conv2d,
            Self::MaxPool2d,
            Self::Embedding,
        ]
    }

    /// Returns `true` if `identifier` matches a known stable op ID or canonical name.
    #[must_use]
    pub fn is_admitted(identifier: &str) -> bool {
        Self::from_stable_id(identifier).is_ok() || Self::from_name(identifier).is_ok()
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.name(), self.stable_id())
    }
}

/// Computes the canonical SHA-256 freeze digest over the operator table and attribute schemas.
///
/// # Errors
/// Returns [`ModelIrError::ArithmeticOverflow`] if hasher exceeds message length bounds.
pub fn compute_operator_table_digest() -> Result<ContentDigest, ModelIrError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(OPERATOR_TABLE_DIGEST_DOMAIN);
    buf.extend_from_slice(&(OPERATOR_SPECS.len() as u32).to_be_bytes());
    for spec in OPERATOR_SPECS {
        buf.extend_from_slice(&(spec.opcode as u32).to_be_bytes());
        buf.extend_from_slice(&(spec.stable_id.len() as u32).to_be_bytes());
        buf.extend_from_slice(spec.stable_id.as_bytes());
        buf.extend_from_slice(&(spec.name.len() as u32).to_be_bytes());
        buf.extend_from_slice(spec.name.as_bytes());
        buf.extend_from_slice(&(spec.min_inputs as u32).to_be_bytes());
        buf.extend_from_slice(&(spec.max_inputs as u32).to_be_bytes());
        buf.extend_from_slice(&(spec.output_count as u32).to_be_bytes());
        buf.extend_from_slice(&(spec.allowed_attributes.len() as u32).to_be_bytes());
        for attr in spec.allowed_attributes {
            buf.extend_from_slice(&(attr.name.len() as u32).to_be_bytes());
            buf.extend_from_slice(attr.name.as_bytes());
            buf.push(attr.attr_type.type_tag());
            buf.push(if attr.required { 1 } else { 0 });
            match attr.default_value {
                Some(def) => {
                    buf.push(1);
                    buf.extend_from_slice(&(def.len() as u32).to_be_bytes());
                    buf.extend_from_slice(def.as_bytes());
                }
                None => {
                    buf.push(0);
                }
            }
        }
    }
    let mut hasher = Sha256Hasher::new();
    hasher.update(&buf);
    let digest_bytes = hasher
        .finalize()
        .map_err(|_| ModelIrError::ArithmeticOverflow {
            operation: "operator table freeze digest calculation",
        })?;
    Ok(ContentDigest::new(DigestAlgorithm::Sha256, digest_bytes))
}

/// Verifies that an actual operator table digest matches the expected freeze digest.
///
/// Pure verification function with zero ambient or mutable process state.
///
/// # Errors
/// Returns [`ModelIrError::InvalidAttribute`] if `actual` does not equal `expected`.
pub fn verify_operator_table_digest(
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), ModelIrError> {
    if actual != expected {
        return Err(ModelIrError::InvalidAttribute {
            node_id: "operator_table".to_string(),
            attr_name: "freeze_digest".to_string(),
            reason: format!(
                "operator table freeze digest diverged: expected {expected}, got {actual}"
            ),
        });
    }
    Ok(())
}

/// Verifies that the live operator table matches the pinned freeze digest.
///
/// # Errors
/// Returns [`ModelIrError::InvalidAttribute`] if the digest has diverged.
pub fn verify_operator_table_frozen() -> Result<(), ModelIrError> {
    let computed = compute_operator_table_digest()?;
    let expected = ContentDigest::parse(OPERATOR_TABLE_FREEZE_DIGEST).map_err(|e| {
        ModelIrError::InvalidAttribute {
            node_id: "operator_table".to_string(),
            attr_name: "freeze_digest".to_string(),
            reason: format!("invalid pinned freeze digest: {e}"),
        }
    })?;
    verify_operator_table_digest(&expected, &computed)
}

/// Verifies that all operators match the baseline identifiers and no tombstones are resurrected.
///
/// # Errors
/// Returns [`ModelIrError::UnknownOperator`] or [`ModelIrError::InvalidAttribute`] on baseline violation.
pub fn verify_operator_baseline() -> Result<(), ModelIrError> {
    if OPERATOR_SPECS.len() != OPERATOR_BASELINE_IDS.len() {
        return Err(ModelIrError::InvalidAttribute {
            node_id: "operator_table".to_string(),
            attr_name: "baseline_count".to_string(),
            reason: format!(
                "operator count {} != baseline count {}",
                OPERATOR_SPECS.len(),
                OPERATOR_BASELINE_IDS.len()
            ),
        });
    }

    for (spec, &expected_id) in OPERATOR_SPECS.iter().zip(OPERATOR_BASELINE_IDS.iter()) {
        if spec.stable_id != expected_id {
            return Err(ModelIrError::InvalidAttribute {
                node_id: "operator_table".to_string(),
                attr_name: "stable_id".to_string(),
                reason: format!(
                    "operator id mismatch: expected {expected_id}, found {}",
                    spec.stable_id
                ),
            });
        }
        for &tombstone in OPERATOR_TOMBSTONES {
            if spec.stable_id == tombstone {
                return Err(ModelIrError::InvalidAttribute {
                    node_id: "operator_table".to_string(),
                    attr_name: "tombstone".to_string(),
                    reason: format!("tombstoned operator id {} resurrected", spec.stable_id),
                });
            }
        }
    }
    Ok(())
}
