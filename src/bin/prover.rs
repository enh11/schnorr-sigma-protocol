use anyhow::Ok;
use k256::{elliptic_curve::{PublicKey}, pkcs8::DecodePublicKey};
use schnorr::prover::{Prover};
use tokio::{io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader}, net::TcpStream};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
        // let s=key_gen(&"sk.pem".to_string(), &"pk.pem".to_string());

    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    let (reader, mut writer) = socket.into_split();
    
    let mut reader = BufReader::new(reader);
// Reading welcome from the server.
    let mut server_msg = String::new();
    reader.read_line(&mut server_msg).await?;
    println!("{}", server_msg);

let mut action = String::new();
let mut stdin = BufReader::new(io::stdin());

stdin.read_line(&mut action).await?;
writer.write_all(action.as_bytes()).await?;
println!("action is {}",action);
match action.trim() {
    "login" => authentication(reader, writer).await,
    "register" => {println!("action is register");
    Ok(())}
    _=> {
        println!("invalid action");
        Ok(())
    }
}
}
pub async fn authentication(mut reader:BufReader<tokio::net::tcp::OwnedReadHalf>, mut writer:tokio::net::tcp::OwnedWriteHalf) -> anyhow::Result<()>{
  // Insert ID and send it to the server.
  let mut server_msg = String::new();
    reader.read_line(&mut server_msg).await?;
    println!("{}", server_msg);
    
    let mut id = String::new();
    let mut stdin_reader = BufReader::new(io::stdin());
    stdin_reader.read_line(&mut id).await?;
    writer.write_all(id.as_bytes()).await?;
// Read response from the server
    let mut server_msg = String::new();
    reader.read_line(&mut server_msg).await?;
    println!("{}", server_msg);

// Initialization of the prover.
    let my_pk = PublicKey::read_public_key_der_file("pk.pem").expect("Error in reading Public Key.");
    let mut prover = Prover::new(my_pk);
// First Round: generate random point.
    let _ = prover.send_commitment_to_random_value(&mut writer).await?;
    //println!("commit {:?}",prover.commitment.unwrap());
// Second Round: read challenge from prover and respond.

let _ = prover.read_challenge(&mut reader).await?;
// Third round: send rG + (sk)cG
let _ = prover.response(&mut writer).await?;
// Read response of identification 
server_msg.clear();
    reader.read_line(&mut server_msg).await?;
    println!("{}", server_msg);

    Ok(())  
}