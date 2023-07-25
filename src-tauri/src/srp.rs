use crate::diffie_hellman::*;
use data_encoding::HEXUPPER;
use rand::Rng;
use rand::RngCore;
use ring::digest;
use session_types::*;
use sha2::Sha256;
use srp::client::SrpClient;
use srp::groups::G_2048;
use srp::server::SrpServer;
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
    pub fn gen_hash(secret: Secret) -> Result<Vec<u8>, ()> {
        let mut rng = rand::rngs::OsRng;
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let client = SrpClient::<Sha256>::new(&G_2048);
        let v = client.compute_verifier(secret.email.as_bytes(), secret.password.as_bytes(), &salt);
        Ok(v)
        //let hex_encode_salt = HEXUPPER.encode(&salt.to_be_bytes()).into_bytes();
        //let hex_encode_pass = HEXUPPER.encode(&secret.password.as_bytes()).into_bytes();
        //let mut ctx = ring::digest::Context::new(&digest::SHA256);
        //ctx.update(&hex_encode_salt);
        //ctx.update(&hex_encode_pass);
        ////parsec ito hex...
        //let mut raw_hash = ctx.finish();
        //let hash : [u8; 8] = raw_hash.as_ref()[..8].try_into().unwrap();
        //let hex_encode: u64 =  u64::from_be_bytes(hash);
        //// debug!("hex encoded sha256 digest is {:#?}", hex_encode);
        //let v: u64 = (secret.g.pow(hex_encode as u32)) % secret.n;
        //Ok(HEXUPPER.encode(&v.to_be_bytes()))
    }
    //send email, A = g**a % N
    fn client_session(secret: Secret, b_pub: Vec<u8>) -> Vec<u8> {
        let mut a = [0u8; 64];
        let mut rng = rand::rngs::OsRng;
        let client = SrpClient::<Sha256>::new(&G_2048);
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let client_v = client
            .process_reply(
                &a,
                secret.email.as_bytes(),
                &secret.n.to_be_bytes(),
                &salt,
                b_pub.as_slice(),
            )
            .unwrap();
        let a_pub = client.compute_public_ephemeral(&a);
        let client_proof = client_v.proof();
        client_proof.to_vec()
    }
    //send salt B = kv + g **b % N
    fn server_session(v: Vec<u8>) -> Result<Vec<u8>, ()> {
        let mut rng = rand::rngs::OsRng;
        let server = SrpServer::<Sha256>::new(&G_2048);
        let mut b = [0u8, 64];
        rng.fill_bytes(&mut b);
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let (salt, b_pub) = (&salt, server.compute_public_ephemeral(&b, &v));
        Ok(b_pub)
    }
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
