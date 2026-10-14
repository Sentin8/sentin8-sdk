// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:SDK
// SPDX-License-Identifier: Apache-2.0

//! MemBus error surface.

use thiserror::Error;

/// Every library failure. Errors bubble to the caller immediately —
/// MemBus never queues and never retries.
#[derive(Debug, Error)]
pub enum MemBusError {
    /// Connection establishment failed (unreachable endpoint, handshake
    /// timeout, PING failure).
    #[error("MemBus connect failed: {0}")]
    Connect(String),
    /// A RESP command failed at the Valkey level.
    #[error("Valkey error: {0}")]
    Valkey(String),
    /// A frame or stream entry could not be decoded.
    #[error("decode error: {0}")]
    Decode(String),
    /// The stream/channel family failed validation before key build.
    #[error("invalid stream family: {0}")]
    InvalidFamily(String),
    /// The consumer group name failed validation.
    #[error("invalid consumer group: {0}")]
    InvalidGroup(String),
    /// The env id is not a UUID — tenant binding rejects it outright.
    #[error("invalid env id (must be a UUID): {0}")]
    InvalidEnv(String),
}
