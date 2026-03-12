use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use k256::{FieldBytes, PublicKey, Scalar, SecretKey, elliptic_curve::{PrimeField, sec1::ToEncodedPoint}, pkcs8::der::Decode};

use crate::prover::Prover;

pub struct ProverSession {
    pub prover: Prover,
    pub stream: TcpStream,
    pub r: Option<Scalar>,
}
impl ProverSession {

    pub async fn connect(
        prover: Prover,
        addr: &str
    ) -> Result<Self, Box<dyn std::error::Error>> {

        let mut stream = TcpStream::connect(addr).await?;

        let pk = prover.pk;
        let encoded = 
            pk.to_encoded_point(false);

        stream.write_all(encoded.as_bytes()).await?;

        println!("Public key sent");

        Ok(Self {
            prover,
            stream,
            r: None,
        })
    }
    pub async fn send_commitment(
        &mut self) -> Result<(), Box<dyn std::error::Error>> {

    let (r, commitment) = self.prover.commit_random_value();

    self.r = Some(r);

    self.stream
        .write_all(&commitment.point.to_encoded_point(false).to_bytes())
        .await?;

    println!("Commitment sent");

    Ok(())
}
pub async fn receive_challenge(
    &mut self
) -> Result<Scalar, Box<dyn std::error::Error>> {

    let mut buf = [0u8; 32];

    self.stream.read_exact(&mut buf).await?;

    let c = FieldBytes::from(buf);
    let c = Scalar::from_repr(c).unwrap();

    println!("Challenge received");

    Ok(c)
}
}