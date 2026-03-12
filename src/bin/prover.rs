use std::ops::Mul;

use clap::{Arg, Command};
use k256::{Scalar,SecretKey, elliptic_curve::{Field, group::prime::PrimeCurveAffine, sec1::ToEncodedPoint}};
use rand_core::OsRng;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use schnorr::prover::Prover;
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
