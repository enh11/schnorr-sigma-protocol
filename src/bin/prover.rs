use std::{io::Bytes, path::Path};

use k256::{Scalar, Secp256k1, elliptic_curve::{PrimeField, PublicKey, SecretKey, sec1::ToEncodedPoint}, pkcs8::{DecodePublicKey, EncodePublicKey, der::{Decode, DecodeValue}}};
use rand_core::OsRng;
use schnorr::{prover::{Prover, key_gen, read_public_key_der_file}, session::ProverSession};
use serde::Serialize;
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, net::TcpStream};
use std::io;
use schnorr::protocol::Message;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    let (reader, mut writer) = socket.into_split();
    
    let mut reader = BufReader::new(reader);
// Reading wellcom from the server.
    let mut server_msg = String::new();
    reader.read_line(&mut server_msg).await?;
    println!("{}", server_msg);

// Insert ID and send it to the server.
    let mut id = String::new();
    io::stdin().read_line(&mut id)?;
    writer.write_all(id.as_bytes()).await?;
// Read response from the server
    let mut server_msg = String::new();
    reader.read_line(&mut server_msg).await?;
    println!("{}", server_msg);

// Initialization of the prover.
    let my_pk = PublicKey::read_public_key_der_file("pk.pem").expect("Error in reading Public Key.");
    let prover = Prover::new(my_pk);
// First Round: generate random point.
    let (r,rg) = prover.commit_random_value();
    println!("commit {:?}",rg.point);
    writer.write_all(&rg.point.to_encoded_point(false).to_bytes()).await?;
// Second Round: read challenge from prover and respond.
let mut buf = [0u8; 32];
reader.read_exact(&mut buf).await?;

// Safe conversion: reduce modulo curve order
let c = Scalar::from_repr(buf.into()).unwrap();

    println!("recieved {:?}",c);

    Ok(())
}