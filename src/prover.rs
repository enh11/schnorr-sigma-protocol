//! This module implements the Prover side of the Schnorr identification protocol.
//! It provides:
//! - Generation of a random commitment
//! - Receiving a challenge from the verifier
//! - Computing the response
//!
//! The Prover requires the corresponding public key and optionally reads the secret key
//! from a `.pem` file to produce valid responses.
use std::{fs::{File}, io::{Write}, path::Path};
use anyhow::Ok;
use crypto_bigint::subtle::{Choice, CtOption};
use k256::{
    ProjectivePoint, PublicKey, Scalar, SecretKey, 
    elliptic_curve::{Field, PrimeField, sec1::ToEncodedPoint}, 
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey}
};
use rand_core::OsRng;
use tokio::{io::{AsyncReadExt, AsyncWriteExt, BufReader}, net::{tcp::{OwnedReadHalf, OwnedWriteHalf}}};

use crate::user::User;

/// A `Prover` participates in a Schnorr identification protocol.
/// 
/// # Overview
/// The `Prover` is initialized with its **public key**. If the prover is honest,
/// they also know the corresponding **secret key**. The secret key can be provided
/// as a `.pem` file for initialization or later use in generating responses.
///
/// The `Prover` maintains internal state for the interactive protocol rounds:
/// 1. **Public Key (`pk`)** - the public key of the prover.
/// 1. **Random secret (`r`)** - a fresh random scalar chosen for each protocol execution.
/// 2. **Commitment (`rG`)** - the elliptic curve point corresponding to the random secret.
/// 3. **Challenge (`c`)** - the scalar sent by the verifier to which the prover must respond.
///
/// # Fields
pub struct Prover {
    /// The public key of the prover.
    pub user: User,  
    
    /// The random secret `r` generated for a protocol session.
    /// This is used to compute the commitment `rG`.
    pub r: Option<Scalar>,  
    
    /// The committed point `rG` corresponding to the random secret `r`.
    pub commitment: CtOption<ProjectivePoint>,  
    
    /// The challenge `c` sent by the verifier.
    /// Used in the computation of the prover's response `z = r + c*sk`.
    pub challenge: CtOption<Scalar>,  
}

impl Prover {
    pub fn new(user:User)->Self{
        Prover {
            user, 
            r: None, 
            commitment:CtOption::new(ProjectivePoint::IDENTITY, Choice::from(0)),
            challenge: CtOption::new(Scalar::ZERO, Choice::from(0)) }
    }
    pub fn read_pkcs8_der_file(&self,sk_path:&Path)->CtOption<Scalar> {
        let sk: Result<SecretKey, k256::pkcs8::Error> = DecodePrivateKey::read_pkcs8_der_file(sk_path);
        Scalar::from_repr(sk.unwrap().to_bytes())
    }
    fn commit_random_value(&self)->(Scalar,ProjectivePoint) {
        let r  =Scalar::random(&mut OsRng);
        let commitment = ProjectivePoint::GENERATOR * r;
        (r,commitment)
    }
    pub async fn send_commitment_to_random_value(
        &mut self,writer:
        &mut OwnedWriteHalf) -> anyhow::Result<()> {
 
        let (r,rg) = self.commit_random_value();
        self.r = Some(r);
        self.commitment= CtOption::new(rg, Choice::from(1));
        let _ =writer.write_all(&rg.to_encoded_point(false).to_bytes()).await;
        Ok(())
}
pub async fn read_challenge(
    &mut self,reader:  
    &mut BufReader<OwnedReadHalf>)->anyhow::Result<()> {

        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf).await?;
        let challenge = Scalar::from_repr(buf.into());
        self.challenge = challenge;
        //println!("received challenge{:?}", challenge);
        Ok(())
}
pub async fn response(
    &self, 
    writer: &mut OwnedWriteHalf)-> anyhow::Result<()>{
    
        let r = self.commitment.unwrap();
        let c = self.challenge.unwrap();
        //Here must be fixed, the path must be build from user id.
        // Try to define the Prover struc using User as item instead of pk.
        let sk = self.read_pkcs8_der_file(Path::new("keys/4737-3790-6725-4182/sk.pem")).unwrap();
        let z = r + ProjectivePoint::GENERATOR * (sk*c);
        //println!("z is {:?}",z);
        writer.write_all(&z.to_encoded_point(false).to_bytes()).await?;
        
        Ok(())
}
}
pub fn key_gen(sk_file_pem:&String,pk_file_pem:&String)-> anyhow::Result<()> {
    let sk = SecretKey::random(&mut OsRng);
    let mut private_key_file = File::create(&sk_file_pem)?;
    let pem = sk.to_pkcs8_der().unwrap();
        private_key_file.write_all(pem.as_bytes())?;
    let pk = sk.public_key().to_public_key_der().unwrap();
    let mut public_key_file = File::create(pk_file_pem)?;
    //let t= hex::encode(sk.public_key().to_encoded_point(false));
    //println!("pk {:?}",t);
    public_key_file.write_all(pk.as_bytes())?;
    //println!("Private key is available in {}",sk_file_pem);

    Ok(())
}
pub fn read_public_key_der_file(pk_path:&Path)->Result<k256::elliptic_curve::PublicKey<k256::Secp256k1>, k256::pkcs8::spki::Error>{
        DecodePublicKey::read_public_key_der_file(pk_path)
    }
