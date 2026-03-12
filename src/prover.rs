use k256::{Scalar,SecretKey, elliptic_curve::{Field, group::prime::PrimeCurveAffine, sec1::ToEncodedPoint}};
use rand_core::OsRng;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

#[allow(dead_code)]

pub struct Prover(SecretKey);

impl Prover {
    pub fn new(sk:SecretKey)->Self{
        Prover(sk)
    }

    pub async fn send_random_point(verifier_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
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
pub fn response(c:Scalar)->Scalar {
    todo!()
}
}
