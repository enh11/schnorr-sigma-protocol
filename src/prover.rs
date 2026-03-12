use k256::{ProjectivePoint, PublicKey, Scalar, SecretKey, elliptic_curve::{Field, group::prime::PrimeCurveAffine, sec1::ToEncodedPoint}};
use rand_core::OsRng;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};

use crate::protocol::Commitment;

#[allow(dead_code)]

pub struct Prover(SecretKey);

impl Prover {
    pub fn new(sk:SecretKey)->Self{
        Prover(sk)
    }
    pub fn extract_pk(&self)-> PublicKey{
        self.0.public_key()

    }
    pub fn commit_sk(&self)->ProjectivePoint {
        self.extract_pk().to_projective()
    }
    pub async fn setup()->Result<(),Box<dyn  std::error::Error>> {
        todo!()
    }
    pub fn commit_random_value(&self)->(Scalar,Commitment) {
        let r  =Scalar::random(&mut OsRng);
        let point = ProjectivePoint::GENERATOR * r;
        let commitment  = Commitment::new(&point);
        (r,commitment)
    }
    pub async fn send_commitment_to_random_value(&self,verifier_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
 
        let p = self.commit_random_value().1.point;

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
