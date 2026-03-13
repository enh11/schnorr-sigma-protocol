
use std::fs;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};

use k256::elliptic_curve::{Field};
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{EncodedPoint, ProjectivePoint, PublicKey, Scalar};
use rand_core::OsRng;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Verifier listening on 127.0.0.1:8080");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Prover connected: {}", addr);

        let (reader, mut writer) = socket.into_split();

        // ask for id
        writer.write_all(b"Enter ID:\n").await?;

        let mut reader = BufReader::new(reader);
        let mut id = String::new();
        reader.read_line(&mut id).await?;
        let id_str = Path::new("users").join(format!("{}.json", id.trim()));

        let data = fs::read_to_string(id_str).expect("error: user not found!");
        let users:Vec<User>= serde_json::from_str(&data)?;

        let user =users.iter().find(|u| u.id == id.trim());
        let pk_user = user.unwrap().pk.clone();
        println!("pk {:?}",pk_user);

        let p = EncodedPoint::from_str(&pk_user);
        let pk = k256::PublicKey::from_encoded_point(&p.unwrap());
        println!("Received ID from prover: {}", id.trim());
    }
}
pub struct Verifier(PublicKey);
impl Verifier {
    pub fn new(pk: PublicKey) -> Self {
        Verifier(pk)
    }
async fn send_random_point(verifier_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random u32 value
    let random_value =Scalar::random(&mut OsRng);
    println!("Generated: {:?}", random_value);
    let p = k256::AffinePoint::generator()*random_value;

    // Connect to the verifier
    let mut stream = TcpStream::connect(verifier_addr).await?;
    // Send the random value as bytes
    stream.write_all(&p.to_encoded_point(false).to_bytes()).await?;
    
    // Wait for verifier response
    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf).await?;
    println!("Verifier responded: {}", String::from_utf8_lossy(&buf[..n]));

    Ok(())
}
pub fn verfy()->bool {
    todo!()
}
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub pk: String,
}