
use schnorr::schnorr_protocol::{Connection, ProtocolState};
use tokio::io::{BufReader};
use tokio::net::{TcpListener, TcpStream};
use schnorr::schnorr_protocol::Action;

#[tokio::main]
async fn main() -> anyhow::Result<()>{

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Verifier listening on 127.0.0.1:8080");

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
