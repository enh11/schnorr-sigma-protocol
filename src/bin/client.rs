use anyhow::Ok;
use k256::{elliptic_curve::{PublicKey}, pkcs8::DecodePublicKey};
use schnorr::prover::{Prover};
use tokio::{io::{AsyncBufReadExt,AsyncWriteExt, BufReader}, net::{TcpStream, tcp::{OwnedReadHalf, OwnedWriteHalf}}};

pub struct ClientConnection {
    pub reader: BufReader<OwnedReadHalf>,
    pub writer: OwnedWriteHalf,
}

impl ClientConnection {
    pub async fn read_line(&mut self) -> anyhow::Result<String> {
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        Ok(line)
    }

    pub async fn write_line(&mut self, msg: &str) -> anyhow::Result<()> {
        self.writer.write_all(msg.as_bytes()).await?;
        Ok(())
    }

    pub async fn read_stdin() -> anyhow::Result<String> {
        let mut input = String::new();
        let mut stdin = BufReader::new(tokio::io::stdin());
        stdin.read_line(&mut input).await?;
        Ok(input)
    }

    //Main run Loop
    pub async fn run(&mut self) -> anyhow::Result<()> {
        // Read welcome message
        let msg = self.read_line().await?;
        println!("{}", msg);

        // Get user action
        let action = Self::read_stdin().await?;
        self.write_line(&action).await?;

        match action.trim() {
            "0" => self.run_authentication().await?,
            "1" => self.run_register().await?,
            _ => println!("Invalid action"),
        }

        Ok(())
    }
pub async fn run_authentication(&mut self)->anyhow::Result<()> {
    //  The server ask for the user ID. 
        let msg = self.read_line().await?;
        println!("{}", msg);

    // The client send it to the server.
        let id = Self::read_stdin().await?;
        self.write_line(&id).await?;

    // Server welcome
        let msg = self.read_line().await?;
        println!("{}", msg);

        // Initialize prover
        let my_pk = PublicKey::read_public_key_der_file("pk.pem")?;
        let mut prover = Prover::new(my_pk);

        // Schnorr protocol
        prover.send_commitment_to_random_value(&mut self.writer).await?;
        prover.read_challenge(&mut self.reader).await?;
        prover.response(&mut self.writer).await?;

        // Final result
        let msg = self.read_line().await?;
        println!("{}", msg);

        Ok(())
    }
pub async fn run_register(&mut self)->anyhow::Result<()> {
    todo!()
}
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    let (reader, writer) = socket.into_split();

    let mut conn = ClientConnection {
        reader: BufReader::new(reader),
        writer,
    };

    conn.run().await
}
