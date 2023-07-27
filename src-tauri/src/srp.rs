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
pub mod srp_handshake {
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

    pub struct Server_Secret {
        pub priv_b: [u8; 2],
        pub server_proof: Vec<u8>,
    }

    pub struct PubKeys {
        pub a: Vec<u8>,
        pub b: Vec<u8>,
    }
    //screw it juast bundle all these and return them in session
    pub struct SrvMsg {
        pub verifier: Vec<u8>,
        pub srv_key : Vec<u8>,
        pub srv_proof: Vec<u8>,
    }

    pub struct CliMsg {
        pub verifier: Vec<u8>,
        pub cli_key : Vec<u8>,
        pub cli_proof: Vec<u7>,

    }
    //N = NIST prime, g = 2, k = 3, email, password
    pub fn negotiate_secret() {}
    //salt as rand int, xh =sha256(salt|password), convert xh to int, gen v = g**x % N
    pub fn gen_hash(secret: &Secret) -> Result<Vec<u8>, ()> {
        let mut rng = rand::rngs::OsRng;
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let client = SrpClient::<Sha256>::new(&G_2048);
        let v = client.compute_verifier(secret.email.as_bytes(), secret.password.as_bytes(), &salt);
        info!("Verifier is {:#?}", v);
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
    pub fn client_session(secret: &Secret, pub_keys: &mut PubKeys) -> Result<Vec<u8>, ()> {
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
                &pub_keys.b,
            )
            .unwrap();
        pub_keys.a = client.compute_public_ephemeral(&a);
        let client_proof = client_v.proof();
        info!("client proof is {:#?}", client_proof);
        Ok(client_proof.to_vec())            
    }
    //send salt B = kv + g **b % N
    pub fn server_session(v: Vec<u8>, pub_keys: &mut PubKeys, server_secret: &mut Server_Secret) -> Result<Vec<u8>, ()> {
        let mut rng = rand::rngs::OsRng;
        let server = SrpServer::<Sha256>::new(&G_2048);
        let mut b = [0u8, 64];
        rng.fill_bytes(&mut b);
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let (salt, b_pub) = (&salt, server.compute_public_ephemeral(&b, &v));
        pub_keys.b = b_pub.clone();
        server_secret.priv_b = b; 
        Ok(b_pub)
    }
    //uH = sha256(A|B) , u = interger of uH
    pub fn server_verify(
        pub_keys: PubKeys,
        priv_b: &[u8],
        verifier: Vec<u8>,
        secret: &Secret,
        proof: Vec<u8>,
    ) {
        let server = SrpServer::<Sha256>::new(&G_2048);
        let server_v = server
            .process_reply(&priv_b, &verifier.as_slice(), &pub_keys.a.as_slice())
            .unwrap();
        info!("client verifying via server");
        server_v.verify_client(&proof.as_slice()).unwrap();
        let server_proof = server_v.proof();
        let server_key = server_v.key();
        info!("Server proof : {:#?}", server_proof);
        info!("Server key : {:#?}", server_key);
    }

    // pub fn client_verify(pub_keys: PubKeys, secret: &Secret, proof: Vec<u8>, priv_a: &[u8], verifier :  {
    //     let client = SrpClient::<Sha256>::new(&G_2048);
    //     info!("server verifying via client");

    // }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[traced_test]
    fn hash_test() {
        let Scrt = srp_handshake::Secret {
            n: 31,
            g: 3,
            k: 2,
            email: String::from("jowbog@gmail.com"),
            password: String::from("sillyorange33342352"),
        };
        let mut srv_secret = srp_handshake::Server_Secret {
            priv_b : [0u8; 2],
            server_proof: vec![0u8; 16],
        };
        let hash = srp_handshake::gen_hash(&Scrt).unwrap();
        let mut pub_k: srp_handshake::PubKeys = srp_handshake::PubKeys {
            a: vec![0u8; 16],
            b: vec![0u8; 16],
        };
        
        let pub_b = srp_handshake::server_session(hash.clone(), &mut pub_k, &mut srv_secret);
        let client_session = srp_handshake::client_session(&Scrt, &mut pub_k);
        let server_v = srp_handshake::server_verify(pub_k, &srv_secret.priv_b, hash, &Scrt, client_session.unwrap());
    }
}
