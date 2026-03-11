
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use clap::{Command};
use clap::Arg;
use k256::elliptic_curve::{Field, SecretKey};
use k256::{PublicKey, Scalar, Secp256k1};
use k256::elliptic_curve::rand_core::OsRng;
use k256::elliptic_curve::sec1::ToEncodedPoint;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Verifier listening on 127.0.0.1:8080");

    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Verifier(PublicKey);
impl Verifier {
    pub fn new(pk:PublicKey)->Self {
        Verifier(pk)
    }
    
}
