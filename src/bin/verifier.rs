
use std::fs;
use std::io::BufRead;
use std::path::Path;
use std::str::FromStr;

use anyhow::Ok;
use crypto_bigint::subtle::CtOption;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};

use k256::elliptic_curve::{Field};
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{EncodedPoint, ProjectivePoint, PublicKey, Scalar, Secp256k1};
use rand_core::OsRng;
use crypto_bigint::subtle::Choice;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()>{

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Verifier listening on 127.0.0.1:8080");
    let (socket, addr) = listener.accept().await?;
    println!("Prover connected to the server: {}\nRunning identification protocol.", addr);

    let (reader, mut writer) = socket.into_split();
         // ask for id
         writer.write_all(b"Enter ID:\n").await?;

         let mut reader = BufReader::new(reader);
         let mut id = String::new();
        reader.read_line(&mut id).await?;
        let id_str = Path::new("users").join(format!("{}.json", id.trim()));

        let data = fs::read_to_string(id_str).expect("error: user not found!");
        writer.write_all(b"user found.\n").await?;
        let users:Vec<User>= serde_json::from_str(&data)?;

        let user =users.iter().find(|u| u.id == id.trim());
        let pk_user = user.unwrap().pk.clone();
        println!("pk {:?}",pk_user);
        let pk = EncodedPoint::from_str(&pk_user).unwrap();
        let pk: PublicKey = PublicKey::from_encoded_point(&pk).unwrap();
        let mut verifier = Verifier::new(pk);
//Read commitment from the prover
        let _ = verifier.read_commitment(&mut reader).await;
        println!("recieved {:?}",verifier.commitment.unwrap());
// Send a Challenge
    let _ = verifier.send_challenge(writer).await;
    println!("challenge {:?}",verifier.challenge.unwrap());
    Ok(())
}
pub struct Verifier {
    pub public_key: PublicKey,   // Y = x·G
    pub commitment: CtOption<ProjectivePoint>, // R
    pub challenge: Option<Scalar>,     // c
}impl Verifier {
    pub fn new(pk: PublicKey) -> Self {
        Verifier { public_key: pk, commitment: CtOption::new(ProjectivePoint::IDENTITY, Choice::from(0)), challenge: None }
    }
    pub async fn send_challenge(&mut self, mut writer: OwnedWriteHalf) -> anyhow::Result<()> {
        let c = Scalar::random(&mut OsRng);
        self.challenge = Some(c);
        writer.write_all(&c.to_bytes()).await?;
        Ok(())
    }
    pub async fn read_commitment(&mut self, reader: &mut BufReader<OwnedReadHalf>) -> anyhow::Result<()> {

        let mut buf = [0u8; 65];
        reader.read_exact(&mut buf).await?;

        let encoded = EncodedPoint::from_bytes(&buf)?;
        let commit = ProjectivePoint::from_encoded_point(&encoded);
        self.commitment = commit;
        println!("received {:?}", commit);
        Ok(())
    }
async fn send_random_point(verifier_addr: &str) -> anyhow::Result<()> {
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