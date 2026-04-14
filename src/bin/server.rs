
use anyhow::Ok;
use schnorr::schnorr_protocol::{Connection, ProtocolState};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use schnorr::schnorr_protocol::Action;

#[tokio::main]
async fn main() -> anyhow::Result<()>{

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Verifier listening on 127.0.0.1:8080");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("Client connected. {}",addr);

        tokio::spawn(async move {
            if let Err(e)= handle_connection(socket).await {
                eprintln!("Error with {}: {:?}",addr,e)
            }
        });
    }

}
async fn handle_connection(socket: TcpStream)->anyhow::Result<()> {
    let (reader, writer) = socket.into_split();
    let mut conn = Connection {
        reader: BufReader::new(reader),
        writer,
        state: ProtocolState::WaitingForId,
    };
         conn.writer.write_all(b"Type 0 to authenticate your self if already registered. Type 1 to register a new user.\n").await?;

    conn.run().await
}
