use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{EncodedPoint, ProjectivePoint};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Verifier listening on 127.0.0.1:8080");

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("Prover connected: {}", addr);

        tokio::spawn(async move {
            let mut buf = [0u8; 65]; // 65 bytes for uncompressed point
            if socket.read_exact(&mut buf).await.is_ok() {
                // Decode the received bytes into a ProjectivePoint
                let encoded = EncodedPoint::from_bytes(&buf).unwrap();
                let r = ProjectivePoint::from_encoded_point(&encoded).unwrap();
                println!("Verifier received R = {:?}", r);

                let _ = socket.write_all(b"Point received").await;
            }
        });
    }
}