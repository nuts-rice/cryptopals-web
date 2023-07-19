use crate::diffie_hellman::*;
use data_encoding::HEXUPPER;
use rand::Rng;
use ring::digest;
use session_types::*;
use tracing::*;
use tracing_test::traced_test;
//refer to http://srp.stanford.edu/design.html
mod srp_handshake {
    use super::*;
    type server = Recv<Secret, Send<Msg, Eps>>;
    type client = <server as HasDual>::Dual;

    pub struct Secret {
        pub n: u64,
        pub g: u64,
        pub k: u64,
        pub email: String,
        pub password: String,
    }
    //TODO: Placeholder type
    pub struct Msg {
        message: String,
    }
    //N = NIST prime, g = 2, k = 3, email, password
    pub fn negotiate_secret() {}
    //salt as rand int, xh =sha256(salt|password), convert xh to int, gen v = g**x % N
    pub fn gen_hash(secret: Secret) -> Result<String, ()> {
        let mut rng = rand::thread_rng();
        let salt: u64 = rng.gen();
        let mut ctx = ring::digest::Context::new(&digest::SHA256);
        ctx.update(salt.to_be_bytes().as_slice());
        ctx.update(secret.password.as_bytes());
        //parse into hex...
        let raw_hash = ctx.finish();
        let hex_encode = HEXUPPER.encode(raw_hash.as_ref());
        debug!("hex encoded sha256 digest is {:#?}", hex_encode);
        // let v: u64 = secret.g.wrapping_pow(hex_encode)
        Ok(String::from("dummy"))
    }
    //send email, A = g**a % N
    fn client_session() {}
    //send salt B = kv + g **b % N
    fn server_session() {}
    //uH = sha256(A|B) , u = interger of uH
    pub fn hash_key() {}
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[traced_test]
    fn hash_test() {
        let scrt = srp_handshake::Secret {
            n: 31,
            g: 3,
            k: 2,
            email: String::from("jowbog@gmail.com"),
            password: String::from("sillyorange33342352"),
        };
        let msg = srp_handshake::gen_hash(scrt);
    }
}
