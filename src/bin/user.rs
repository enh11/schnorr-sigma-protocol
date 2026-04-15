use schnorr::user::User;

fn main() {
    let c =User::from_data("mandi","mandi@gmail.com");
    let _ = c.unwrap().get_json();

    
}