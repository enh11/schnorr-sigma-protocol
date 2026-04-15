use std::path::Path;

use k256::{PublicKey, Secp256k1, elliptic_curve::{SecretKey, sec1::ToEncodedPoint}, pkcs8::{EncodePrivateKey, EncodePublicKey}};
use rand::RngExt;
use rand_core::{OsRng};
use serde::{Deserialize, Serialize};
use tokio::fs;

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    pub pk: String,
}
pub enum LoginProtocol {
    WaitingForUserName,
    UserGenerated {pk:PublicKey}
    
}

impl User {
    pub fn new() -> Self {
        User {
            id: String::new(),
            name: String::new(),
            email: String::new(),
            pk: String::new()
        }
    }
    pub fn from_data(user_name:&str,email:&str)-> anyhow::Result<Self>{


        let id = generate_id();
        println!("id {}",id);
        let user_id = format!("{}-{}",user_name,id);

 // 1. Create user directory (blocking is OK here since fn is sync)
    let dir = format!("keys/{}", user_id);
    std::fs::create_dir_all(&dir)?;

        // 2. Generate keypair
        let sk: SecretKey<Secp256k1> = SecretKey::random(&mut OsRng);
        
        let pk = sk.public_key();
        let encoded = pk.to_encoded_point(false); // false = uncompressed (65 bytes)
        let pk_hex = hex::encode(encoded.as_bytes());

        let user = User { 
            id:id, 
            name:user_name.to_owned(),
            email: email.to_owned(),
            pk: pk_hex.to_owned()};

       // 3. Serialize keys
    let sk_pem = sk.to_pkcs8_der()?;
    let pk_pem = pk.to_public_key_der()?;

    // 4. Write private key safely
    let sk_path = format!("{}/sk.pem", dir);
    let pk_path = format!("{}/pk.pem", dir);


    std::fs::write(sk_path, sk_pem.as_bytes())?;
    std::fs::write(pk_path, pk_pem.as_bytes())?;
    Ok(user)       
        
    }
    pub fn get_json(&self) -> anyhow::Result<()> {
    // Serialize self
    let json = serde_json::to_string_pretty(self)?;

    // Ensure directory exists
    std::fs::create_dir_all("users")?;

    // Build file name
    let file_name = format!("{}.json", self.id);

    // Build path
    let path = Path::new("users").join(file_name);

    // Write file
    std::fs::write(path, json)?;

    Ok(())
}
}
fn generate_id() -> String {
    let mut rng = rand::rng();
    (0..4)
        .map(|_| {
            let number = rng.random_range(1000..10000);
            number.to_string()
        })
        .collect::<Vec<_>>()
        .join("-")
}


