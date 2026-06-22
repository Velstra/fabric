//! Generated gRPC types and stubs for the Velstra control-plane API.
//!
//! The `.proto` lives in `proto/velstra.proto` and is compiled by `build.rs`.
//! Both the controller (`velstra-controller`) and the agent (`velstra`)
//! depend on this crate so they share one definition of the wire format.
//!
//! `result_large_err` is allowed crate-wide: tonic's generated stubs return
//! `Result<_, tonic::Status>`, and `Status` is intentionally a large enum.
#![allow(clippy::result_large_err)]

/// The `velstra.v1` package: messages, the `VelstraControl` service client
/// (`velstra_control_client`) and server (`velstra_control_server`).
pub mod v1 {
    tonic::include_proto!("velstra.v1");
}

pub use v1::*;
