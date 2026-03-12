use k256::{ProjectivePoint, Scalar};

pub struct Commitment {
    pub point: ProjectivePoint,
}
impl Commitment {
    pub fn new(point:&ProjectivePoint)->Self{
        Commitment { point: *point }
    }
}

pub struct Challenge {
    pub c: Scalar,
}

pub struct Response {
    pub s: Scalar,
}