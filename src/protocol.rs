use k256::{ProjectivePoint, Scalar};

pub struct Commitment {
    pub R: ProjectivePoint,
}

pub struct Challenge {
    pub c: Scalar,
}

pub struct Response {
    pub s: Scalar,
}