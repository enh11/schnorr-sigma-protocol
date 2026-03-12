use std::path::Path;

use schnorr::{prover::{Prover, read_public_key_der_file}, session::ProverSession};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let addr = "127.0.0.1:8080";
    let pk_path = Path::new("pk.pem");
    let pk = read_public_key_der_file(pk_path).unwrap();
    let prover = Prover::new(pk);

    let mut session = ProverSession::connect(prover, addr).await?;

    session.send_commitment().await?;

    let c = session.receive_challenge().await?;

    //session.send_response(c).await?;

    Ok(())
}