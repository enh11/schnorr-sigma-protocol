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

use std::{path::Path, str::FromStr};
use anyhow::Ok;
use k256::{EncodedPoint, PublicKey, elliptic_curve::{sec1::FromEncodedPoint}};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use crate::{user::User, verifier::Verifier};
use tokio::net::tcp::{OwnedReadHalf,OwnedWriteHalf};

pub enum Action {
    Invalid,
    Register,
    Authentication    
}
/// Represents the current state of the identification protocol.
///
/// Each variant corresponds to a specific phase in the verifier's interaction
/// with a prover. Transitions between states enforce correct protocol execution.
/// 
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
        user: User,
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
    pub async fn read_action(&mut self) -> anyhow::Result<Action> {
    let mut action = String::new();
    self.reader.read_line(&mut action).await?;

    Ok(match action.trim() {
        "0" => Action::Authentication,
        "1" => Action::Register,
        _ => Action::Invalid,
    })
}
    pub async fn handle_waiting_for_id(mut self) -> anyhow::Result<Self> {
        // ask for id
    self.writer.write_all(b"Enter ID:\n").await?;

    let mut id = String::new();
    self.reader.read_line(&mut id).await?;

    //let id = id.trim();

// build path
let path = Path::new("users").join(format!("{}.json", id.trim()));

// 1. safely handle missing file
let data = match tokio::fs::read_to_string(&path).await {
    std::result::Result::Ok(d) => d,
    std::result::Result::Err(_) => {
        self.writer.write_all(b"User not found\n").await?;
        return Ok(self);
    }
};

// 2. parse JSON 
let user:User = serde_json::from_str(&data)?;

// // 3. find user safely
// let user = match users.iter().find(|u| u.id == id) {
//     Some(u) => u.clone(),
//     None => {
//         self.writer.write_all(b"User mismatch\n").await?;
//         return Ok(self);
//     }
// };

self.writer.write_all(b"User found.\n").await?;

        println!("user is {:?}", &user);

        // let pk_user = user.pk.clone();
        // let pk = EncodedPoint::from_str(&pk_user).unwrap();
        // let pk: PublicKey = PublicKey::from_encoded_point(&pk).unwrap();


        self.state = ProtocolState::UserLoaded { user };
        Ok(self)
    }
    pub async fn handle_user_loaded(mut self) -> anyhow::Result<Self> {
        
        let str_pk = match &self.state {
            ProtocolState::UserLoaded { user } => &user.pk,
            _ => unreachable!(),
        };
        let pk =EncodedPoint::from_str(&str_pk).unwrap();
        let pk = PublicKey::from_encoded_point(&pk).unwrap();
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
            .verify(&mut self.reader)
            .await?;

        if success {
                self.writer.write_all(b"ACCEPTED\n").await?;
                self.state = ProtocolState::Verified;
            } else {
                self.writer.write_all(b"REJECTED\n").await?;
                self.state = ProtocolState::Failed;
            }

        Ok(self)
    }

pub async fn run(mut self) -> anyhow::Result<()> {
        
    loop {
        match self.read_action().await? {
            Action::Authentication => {
                self = self.run_schnorr().await?;
            }

            Action::Register => {
                self = self.run_register().await?;
            }

            Action::Invalid => {
                self.writer.write_all(b"Invalid action\n").await?;
            }
        }
    }
}
pub async fn run_schnorr(mut self) -> anyhow::Result<Self> {
    self = self.handle_waiting_for_id().await?;
    self = self.handle_user_loaded().await?;
    self = self.handle_commitment().await?;
    self = self.handle_challenge().await?;
    Ok(self)
}
pub async fn run_register(mut self) -> anyhow::Result<Self> {

    //THIS MUST BE FIXED

    let mut user = String::new();
    self.reader.read_line(&mut user).await?;

    println!("received user {}",user);
    let user = User::new_from_json(&user)?;
// 3. Save user
    user.get_json()?;

    // 4. Respond to client
    self.writer
        .write_all(b"REGISTERED\n")
        .await?;

    Ok(self)
}
}