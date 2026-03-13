use std::path::Path;

use k256::{Secp256k1, elliptic_curve::{PublicKey, SecretKey, sec1::ToEncodedPoint}, pkcs8::{DecodePublicKey, EncodePublicKey}};
use rand_core::OsRng;
use schnorr::{prover::{Prover, key_gen, read_public_key_der_file}, session::ProverSession};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, net::TcpStream};
use std::io;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
key_gen(&"sk.pem".to_string(), &"pk.pem".to_string());
let pk: Result<PublicKey<Secp256k1>, k256::pkcs8::spki::Error> = PublicKey::read_public_key_der_file("pk.pem");
println!("pk {:?}",pk.unwrap().to_encoded_point(false).to_string());
    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    let (reader, mut writer) = stream.into_split();

    let mut reader = BufReader::new(reader);

    let mut server_msg = String::new();
    reader.read_line(&mut server_msg).await?;

    print!("{}", server_msg);

    let mut id = String::new();
    io::stdin().read_line(&mut id)?;

    writer.write_all(id.as_bytes()).await?;

    Ok(())
}