use std::{fs::{self, File}, io::Write};

use k256::{PublicKey, Secp256k1, elliptic_curve::{SecretKey, consts::P256, sec1::ToEncodedPoint}, pkcs8::{EncodePrivateKey, EncodePublicKey}};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug,Clone,PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub name: String,
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
            pk: String::new()
        }
    }
    pub fn from_str(user_name:&str)-> anyhow::Result<Self>{

        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);

        let id = hex::encode(bytes);
        let user_id = format!("{}-{}",user_name,id);

        // 1. Create user directory
        let dir = format!("keys/{}", user_id);
        let _= fs::create_dir_all(&dir);

        // 2. Generate keypair
        let sk: SecretKey<Secp256k1> = SecretKey::random(&mut OsRng);
        
        let pk = sk.public_key();
        let encoded = pk.to_encoded_point(false); // false = uncompressed (65 bytes)
        let pk_hex = hex::encode(encoded.as_bytes());

        let user = User { id:id, 
            name:user_name.to_string(),
            pk: pk_hex};

       // 3. Serialize keys
    let sk_pem = sk.to_pkcs8_der()?;
    let pk_pem = pk.to_public_key_der()?;

    // 4. Write private key safely
    let sk_path = format!("{}/sk.pem", dir);
    let pk_path = format!("{}/pk.pem", dir);

    {
        let mut file = File::create(&sk_path)?;
        file.write_all(sk_pem.as_bytes())?;
    }

    {
        let mut file = File::create(&pk_path)?;
        file.write_all(pk_pem.as_bytes())?;
    }

    Ok(user)       
        
    }
}


