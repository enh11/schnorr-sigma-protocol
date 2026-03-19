use std::path::Path;
use std::str::FromStr;

use anyhow::Ok;
use schnorr::schnorr_protocol::{Connection, ProtocolState};
use schnorr::verifier::Verifier;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use k256::elliptic_curve::sec1::{FromEncodedPoint};
use k256::{EncodedPoint, PublicKey};

use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::io::{AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()>{

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Verifier listening on 127.0.0.1:8080");
    // let (socket, addr) = listener.accept().await?;
    //println!("Prover connected to the server: {}\nRunning identification protocol.", addr);

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Prover connected. {}",addr);

        tokio::spawn(async move {
            if let Err(e)= handle_connection(socket).await {
                eprintln!("Error with {}: {:?}",addr,e)
            }
        });
    }

}
async fn handle_connection(socket: TcpStream)->anyhow::Result<()> {
     let (reader, writer) = socket.into_split();
    let conn = Connection {
        reader: BufReader::new(reader),
        writer,
        state: ProtocolState::WaitingForId,
    };

    conn.run().await
}
