//! # Verifier Protocol State Machine
//!
//! This module implements the server-side logic for a Schnorr identification
//! protocol using an explicit state machine.
//!
//! ## Overview
//!
//! Each client connection progresses through a sequence of well-defined states:
//!
//! 1. `WaitingForId` – the server requests and receives a user ID
//! 2. `UserLoaded` – the user's public key is loaded from storage
//! 3. `CommitmentReceived` – the prover sends a commitment
//! 4. `ChallengeSent` – the verifier sends a random challenge
//! 5. `Verified` / `Failed` – authentication result
//!
//! The state machine ensures that protocol steps are executed in the correct
//! order and prevents invalid transitions.
//!
//! ## Concurrency
//!
//! Each connection is handled independently in its own async task, allowing
//! multiple provers to interact with the verifier concurrently.
//!
//! ## Notes
//!
//! - This implementation separates protocol logic from networking
//! - Each state transition is explicit and validated
//! - Designed to be extended with timeouts, retries, or additional checks

use std::{any, path::Path, str::FromStr};
use anyhow::Ok;
use k256::{EncodedPoint, PublicKey, elliptic_curve::sec1::FromEncodedPoint};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use crate::verifier::Verifier;
use tokio::net::tcp::{OwnedReadHalf,OwnedWriteHalf};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub pk: String,
}

/// Represents the current state of the identification protocol.
///
/// Each variant corresponds to a specific phase in the verifier's interaction
/// with a prover. Transitions between states enforce correct protocol execution.
pub enum ProtocolState {
    /// Initial state.
    ///
    /// The verifier is waiting for the prover to send an identifier to authenticate his/her self (user ID).
    WaitingForId,

    /// The user has been successfully loaded.
    ///
    /// Contains the public key associated with the provided user ID.
    UserLoaded {
        /// Public key of the user, used for verification.
        pk: PublicKey,
    },

    /// The prover's commitment has been received.
    ///
    /// The verifier has initialized its internal state and is ready
    /// to issue a challenge.
    CommitmentReceived {
        /// Verifier instance holding protocol data (e.g. commitment).
        verifier: Verifier,
    },

    /// The challenge has been sent to the prover.
    ///
    /// The verifier is waiting for the prover's response.
    ChallengeSent {
        /// Verifier instance holding challenge and commitment.
        verifier: Verifier,
    },

    /// Authentication succeeded.
    ///
    /// The prover has demonstrated knowledge of the secret key.
    Verified,

    /// Authentication failed.
    ///
    /// The prover did not produce a valid response.
    Failed,
}

/// Represents a single client connection.
///
/// This struct encapsulates:
/// - the network I/O (reader and writer)
/// - the current protocol state
///
/// Each connection progresses through the [`ProtocolState`] state machine
/// independently.
pub struct Connection {
    /// Buffered reader for incoming data from the prover.
    pub reader: BufReader<OwnedReadHalf>,

    /// Writer for sending data to the prover.
    pub writer: OwnedWriteHalf,

    /// Current state of the protocol for this connection.
    pub state: ProtocolState,
}
impl Connection {
    pub async fn handle_waiting_for_action(mut self)->anyhow::Result<Self> {
        self.writer
            .write_all(b"Choose action: [login/register]\n")
            .await?;
    Ok(self)
        
    }
    pub async fn handle_waiting_for_id(mut self) -> anyhow::Result<Self> {
        // ask for id
        self.writer.write_all(b"Enter ID:\n").await?;

        let mut id = String::new();
        self.reader.read_line(&mut id).await?;
        let id = id.trim();

        let id_str = Path::new("users").join(format!("{}.json", id.trim()));

        let data = tokio::fs::read_to_string(id_str).await?;
        self.writer.write_all(b"user found.\n").await?;
        let users:Vec<User>= serde_json::from_str(&data)?;

        let user =users.iter().find(|u| u.id == id.trim());
        let pk_user = user.unwrap().pk.clone();
        println!("pk {:?}",pk_user);
        let pk = EncodedPoint::from_str(&pk_user).unwrap();
        let pk: PublicKey = PublicKey::from_encoded_point(&pk).unwrap();


        self.state = ProtocolState::UserLoaded { pk };
        
        Ok(self)
    }
    pub async fn handle_user_loaded(mut self) -> anyhow::Result<Self> {
        
        let pk = match &self.state {
            ProtocolState::UserLoaded { pk } => pk.clone(),
            _ => unreachable!(),
        };

        let mut verifier = Verifier::new(pk);

        verifier.read_commitment(&mut self.reader).await?;

        self.state = ProtocolState::CommitmentReceived { verifier };
        Ok(self)
    }
    pub async fn handle_commitment(mut self) -> anyhow::Result<Self> {
        
        let mut verifier = match self.state {
            ProtocolState::CommitmentReceived { verifier } => verifier,
            _ => unreachable!(),
        };

        verifier.send_challenge(&mut self.writer).await?;

        self.state = ProtocolState::ChallengeSent { verifier };
        Ok(self)
    }
    pub async fn handle_challenge(mut self) -> anyhow::Result<Self> {

        let verifier = match self.state {
            ProtocolState::ChallengeSent { verifier } => verifier,
            _ => unreachable!(),
        };
        let success = verifier
            .verify(&mut self.reader, &mut self.writer)
            .await?;

        self.state = if success {
            ProtocolState::Verified
            } else {
            ProtocolState::Failed
            };

    Ok(self)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let conn = self.handle_waiting_for_id().await?;
        let conn = conn.handle_user_loaded().await?;
        let conn = conn.handle_commitment().await?;
        let _conn = conn.handle_challenge().await?;
        Ok(())
}
}