use std::ops::Mul;

use clap::{Arg, Command};
use k256::{PublicKey, Scalar, SecretKey, elliptic_curve::{Field, group::prime::PrimeCurveAffine, sec1::ToEncodedPoint}};
use rand_core::OsRng;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use schnorr::prover::Prover;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let prover:Prover;
    let addr:&str;
    let matches = Command::new("schnorr")
        .version("0.1")
        .author("Enrico Talotti")
        .about("Identification and signature from Sigma protocol")
        .subcommand(
            Command::new("setup")
                .about("Initialization of Schnorr's protocol.")
                .arg(
                    Arg::new("skey")
                    .help("Secret key")
                    .long("sk")
                    .required(true)
                )
                // .arg(
                //     Arg::new("pkey")
                //     .help("Public key")
                //     .long("pk")
                //     .required(true)
                // )
                .arg(
                Arg::new("address")
                    .help("Address of the verifier. Default is 127.0.0.1:8080")
                    .short('a')

                )
            )
        .subcommand(
            Command::new("round-one")
                .about("Run the first round of the protocol")
        ).get_matches();

match matches.subcommand() {

    Some(("setup", sub_m)) => {

        addr = sub_m
            .get_one::<String>("address")
            .unwrap();
        let sk_string = sub_m
            .get_one::<String>("skey")
            .unwrap();
        let sk= SecretKey::from_slice(&hex::decode(sk_string)? )?;

        prover = Prover::new(sk);
        let pk = prover.extract_pk();

        // Connect to the verifier
        let mut stream = TcpStream::connect(addr).await?;
        // Send the random value as bytes
        stream.write_all(&pk.to_encoded_point(false).to_bytes()).await?;
    }

    Some(("round-one", sub_m)) => {

        let addr = sub_m
            .get_one::<String>("address")
            .unwrap();

        // call commitment logic
    }

    _ => {}
}

    Ok(())
}
