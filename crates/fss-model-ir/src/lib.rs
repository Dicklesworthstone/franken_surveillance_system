//! Deterministic, frozen Model Operator Intermediate Representation (IR) v1.
//!
//! Part of the Franken Surveillance System (FSS) pure-Rust model pipeline.
//! Enforces a closed, stable operator set, typed attributes, checked dtype/shape
//! inference over `fss-tensor` types, cycle-free DAG validation, and deterministic
//! canonical encoding under the registered `fss.model_ir.v1` digest domain.

#![forbid(unsafe_code)]

extern crate alloc;

pub mod attribute;
pub mod canonical;
pub mod error;
pub mod graph;
pub mod node;
pub mod op;
pub mod port;
pub mod shape_inference;
pub mod validator;

pub use attribute::{AttrValue, AttributeMap};
pub use canonical::{MODEL_IR_DIGEST_DOMAIN, compute_model_ir_digest, encode_canonical_model_ir};
pub use error::ModelIrError;
pub use graph::{ModelIrGraph, ModelIrGraphBuilder, ModelIrVersion};
pub use node::GraphNode;
pub use op::OpCode;
pub use port::TensorPort;
pub use shape_inference::{broadcast_shapes, infer_operator_outputs};
pub use validator::GraphValidator;
