use std::ops::Mul;

use k256::elliptic_curve::Field;
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
        let (mut socket, addr) = listener.accept().await?;
        println!("Prover connected: {}", addr);

        tokio::spawn(async move {
            let mut buf = [0u8; 65]; // 65 bytes for uncompressed point
            if socket.read_exact(&mut buf).await.is_ok() {
                // Decode the received bytes into a ProjectivePoint
                let encoded = EncodedPoint::from_bytes(&buf).unwrap();
                let r = ProjectivePoint::from_encoded_point(&encoded).unwrap();
                println!("Verifier received R = {:?}", r);
                let _ = socket.write_all(b"Point received").await;
            }
        });
    }
}

pub struct Verifier(PublicKey);
impl Verifier {
    pub fn new(pk:PublicKey)->Self {
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
}