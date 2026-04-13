use k256::PublicKey;
#[derive(Debug,PartialEq, Eq)]
pub struct User {
    id: String,
    pk: PublicKey
}