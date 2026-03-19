use std::path::Path;
use std::str::FromStr;

use anyhow::Ok;
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
    let (reader, mut writer) = socket.into_split();
         // ask for id
         writer.write_all(b"Enter ID:\n").await?;

         let mut reader = BufReader::new(reader);
         let mut id = String::new();
        reader.read_line(&mut id).await?;
        let id_str = Path::new("users").join(format!("{}.json", id.trim()));

        let data = tokio::fs::read_to_string(id_str).await?;
        writer.write_all(b"user found.\n").await?;
        let users:Vec<User>= serde_json::from_str(&data)?;

        let user =users.iter().find(|u| u.id == id.trim());
        let pk_user = user.unwrap().pk.clone();
        println!("pk {:?}",pk_user);
        let pk = EncodedPoint::from_str(&pk_user).unwrap();
        let pk: PublicKey = PublicKey::from_encoded_point(&pk).unwrap();
        let mut verifier = Verifier::new(pk);
//Read commitment from the prover
        let _ = verifier.read_commitment(&mut reader).await?;
        //println!("recieved {:?}",verifier.commitment.unwrap());
// Send a Challenge
    let _ = verifier.send_challenge(&mut writer).await?;
   // println!("challenge {:?}",verifier.challenge.unwrap());
    // Read response
let _ =verifier.verify(&mut reader,&mut writer).await?;
    Ok(())
}
#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub pk: String,
}