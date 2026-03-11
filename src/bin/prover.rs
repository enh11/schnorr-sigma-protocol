use std::ops::Mul;

use clap::{Arg, Command};
use k256::{Scalar,SecretKey, elliptic_curve::{Field, group::prime::PrimeCurveAffine, sec1::ToEncodedPoint}};
use rand_core::OsRng;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("schnorr")
        .version("0.1")
        .author("Enrico Talotti")
        .about("Identification and signature from Sigma protocol")
        .subcommand(
            Command::new("round-one")
                .about("Run the first round of the protocol")
                .arg(
                    Arg::new("address")
                        .help("The verifier address. Default value is 127.0.0.1:8080")
                        .default_value("127.0.0.1:8080")
                
                )
        ).get_matches();
            if let Some(("round-one", sub_m)) = matches.subcommand() {
        let addr = sub_m.get_one::<String>("address").unwrap();
        Prover::send_random_point(addr).await?;
    }

    Ok(())
}
#[allow(dead_code)]
pub struct Prover(SecretKey);
impl Prover {
    pub fn new(sk:SecretKey)->Self{
        Prover(sk)
    }

    async fn send_random_point(verifier_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Generate a random u32 value
    let random_value =Scalar::random(&mut OsRng);
    println!("Generated: {:?}", random_value);
    let p = k256::AffinePoint::generator().mul(random_value);

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
pub fn response(c:Scalar)->Scalar {
    todo!()
}
}
