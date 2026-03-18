use std::{fs::{self, File}, io::Write, path::Path};

use crypto_bigint::subtle::{Choice, CtOption};
use k256::{ProjectivePoint, PublicKey, Scalar, SecretKey, elliptic_curve::{Field, sec1::ToEncodedPoint}, pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, der::EncodeRef}};
use rand_core::OsRng;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpStream, tcp::OwnedWriteHalf}};

use crate::protocol::Commitment;

#[allow(dead_code)]
/// Prover is initialized with its PublicKey.
/// If he is not cheating, then he knows the corresponding SecretKey.
/// Here, we will provide the SecretKey as a .pem file.
pub struct Prover{
    pub public_key: PublicKey,  // The public key of the prover 
    pub r: Option<Scalar>, // The random secret r.
    pub commitment: CtOption<ProjectivePoint>,// The committed point rG.
    pub challenge: Option<Scalar> // The challenge sent by the verifier.
}
impl Prover {
    pub fn new(pk:PublicKey)->Self{
        Prover { 
            public_key: pk, 
            r: None, 
            commitment:CtOption::new(ProjectivePoint::IDENTITY, Choice::from(0)),
            challenge: None }
    }
    pub fn read_pkcs8_der_file(sk_path:&Path)->Result<k256::elliptic_curve::SecretKey<k256::Secp256k1>, k256::pkcs8::Error> {
        DecodePrivateKey::read_pkcs8_der_file(sk_path)
    }
    
    pub fn commit_sk(&self)->ProjectivePoint {
        self.public_key.to_projective()
    }
    fn commit_random_value(&self)->(Scalar,ProjectivePoint) {
        let r  =Scalar::random(&mut OsRng);
        let commitment = ProjectivePoint::GENERATOR * r;
        
        (r,commitment)
    }
    pub async fn send_commitment_to_random_value(&mut self,mut writer:OwnedWriteHalf) -> anyhow::Result<()> {
 
        let (r,rg) = self.commit_random_value();
        self.r = Some(r);
        writer.write_all(&rg.to_encoded_point(false).to_bytes()).await?;
        Ok(())
}
pub fn response(c:Scalar)->Scalar {
    todo!()
}
}
pub fn key_gen(sk_file_pem:&String,pk_file_pem:&String)-> std::io::Result<()> {
    let sk = SecretKey::random(&mut OsRng);
    let mut private_key_file = File::create(&sk_file_pem)?;
    let pem = sk.to_pkcs8_der().unwrap();
        private_key_file.write_all(pem.as_bytes())?;
    let pk = sk.public_key().to_public_key_der().unwrap();
    let mut public_key_file = File::create(pk_file_pem)?;
        public_key_file.write_all(pk.as_bytes())?;
    println!("Private key is available in {}",sk_file_pem);

    Ok(())
}
pub fn read_public_key_der_file(pk_path:&Path)->Result<k256::elliptic_curve::PublicKey<k256::Secp256k1>, k256::pkcs8::spki::Error>{
        DecodePublicKey::read_public_key_der_file(pk_path)
    }
