use clap::builder::Str;
use k256::{ProjectivePoint, Scalar, elliptic_curve::Field};
use rand_core::OsRng;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    ID{ id:String},
    Commit { R: u64 },
    Challenge { c: u64 },
    Response { s: u64 },
}
pub struct Commitment {
    pub point: ProjectivePoint,
}
impl Commitment {
    pub fn new(point:&ProjectivePoint)->Self{
        Commitment { point: *point }
    }
    pub fn new_prover_commitment()->(Scalar,Commitment) {
        let r  =Scalar::random(&mut OsRng);
        let point = ProjectivePoint::GENERATOR * r;
        let commitment  = Commitment::new(&point);
        (r,commitment)
    }
}
