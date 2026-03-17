
use std::fs;
use std::path::Path;
use std::str::FromStr;

use anyhow::Ok;
use k256::elliptic_curve::group::GroupEncoding;
use k256::pkcs8::der::EncodeValue;
use schnorr::prover::Prover;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};

use k256::elliptic_curve::{Field};
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{EncodedPoint, ProjectivePoint, PublicKey, Scalar, Secp256k1};
use rand_core::OsRng;
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
        let prover = Prover::new(pk);
//Read commitment from the prover
        let mut buf = [0u8; 65]; 
        reader.read_exact(&mut buf).await?;
        let encoded = EncodedPoint::from_bytes(&buf).unwrap();
        let commit = ProjectivePoint::from_encoded_point(&encoded).unwrap();
        println!("recieved {:?}",commit);
// Send a Challeng
    let c = Scalar::random(&mut OsRng);
    writer.write_all(&c.to_bytes()).await?;
    println!("challeng {:?}",c);



        
    Ok(())

    // loop {
    //     let (socket, addr) = listener.accept().await?;
    //     println!("Prover connected: {}", addr);

    //     let (reader, mut writer) = socket.into_split();

    //     // ask for id
    //     writer.write_all(b"Enter ID:\n").await?;

    //     let mut reader = BufReader::new(reader);
    //     let mut id = String::new();
    //     reader.read_line(&mut id).await?;
    //     let id_str = Path::new("users").join(format!("{}.json", id.trim()));

    //     let data = fs::read_to_string(id_str).expect("error: user not found!");
    //     let users:Vec<User>= serde_json::from_str(&data)?;

    //     let user =users.iter().find(|u| u.id == id.trim());
    //     let pk_user = user.unwrap().pk.clone();
    //     println!("pk {:?}",pk_user);

    //     let p = EncodedPoint::from_str(&pk_user);
    //     let pk = k256::PublicKey::from_encoded_point(&p.unwrap());
    //     println!("Received ID from prover: {}", id.trim());
    // }
}
pub struct Verifier(PublicKey);
impl Verifier {
    pub fn new(pk: PublicKey) -> Self {
        Verifier(pk)
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