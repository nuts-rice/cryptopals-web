use anyhow::{Error, Result};

use num::{bigint::RandBigInt, BigInt, BigUint, One, Zero, bigint::ToBigInt};
use rand::Rng;
use std::str::FromStr;
#[derive(Clone, Debug)]
pub struct DsaPublic {
    p: BigUint,
    q: BigUint,
    g: BigUint,
}

pub struct DsaKeyPair {
    pub public: DsaPublic,
    pub pub_key: BigUint,
    key: BigUint,
}

pub struct DsaSignature {
    pub r: BigUint,
    pub s: BigUint,
}

impl Default for DsaPublic {
    fn default() -> Self {
        DsaPublic {
            p: BigUint::parse_bytes(
                &b"    
        800000000000000089e1855218a0e7dac38136ffafa72eda7\
        859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
        2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
        ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
        b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
        1a584471bb1"
                    .as_ref(),
                16,
            )
            .unwrap(),
            q: BigUint::parse_bytes(&b"f4f47f05794b256174bba6e9b396a7707e563c5b".as_ref(), 16)
                .unwrap(),
            g: BigUint::parse_bytes(
                &b"\
                5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
        458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
        322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
        0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
        878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
        9fc95302291"
                    .as_ref(),
                16,
            )
            .unwrap(),
        }
    }
}

impl DsaKeyPair {
    pub fn key_gen() -> Self {
        let public = DsaPublic::default();
        let mut rng = rand::thread_rng();
        let mut privKey: BigUint = rng.gen_biguint_range(&BigUint::one(), &public.p);
        let mut nonce: BigUint = rng.gen_biguint_range(&BigUint::one(), &public.p);
        let pubKey = public.g.modpow(&privKey, &public.p);
        DsaKeyPair {
            public,
            pub_key: pubKey,
            key: privKey,
        }
    }

    //TODO: move this somewhere else
    pub fn mod_inv(a: &BigUint, n: BigUint) -> Option<BigUint> {

        let a_ = &a.to_bigint().unwrap();
    let n_ = &n.to_bigint().unwrap();
    let (r, _, mut t) = egcd(n_, a_);
    if r.is_one() {
        if t.is_negative() {
            t += n_;
        }
        Option::Some(t.to_biguint().unwrap())
    } else {
        Option::None
    }
}


pub fn egcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut r_prev, mut r) = (a.clone(), b.clone());
    let (mut s_prev, mut s) = (BigInt::one(), BigInt::zero());
    let (mut t_prev, mut t) = (BigInt::zero(), BigInt::one());
    while !r.is_zero() {
        let q = &r_prev / &r;
        let tmp = &r_prev - &q * &r;
        r_prev = r;
        r = tmp;
        let tmp = &s_prev - &q * &s;
        s_prev = s;
        s = tmp;
        let tmp = &t_prev - &q * &t;
        t_prev = t;
        t = tmp;
    }

    (r_prev, s_prev, t_prev)
}

    
    pub fn mod_sub(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let a = a.mod_floor(n);
    let b = b.mod_floor(n);
    if a >= b {
        a - b
    } else {
        n - (b - a)
    }
}

    //See challange 44
    //overview on recovering k: https://fortenf.org/e/ctfs/pwn/crypto/2018/05/07/defconquals2018-official.html
    //https://iacr.org/submit/files/slides/2022/tches/ches2022/1_34/slides.pdf
    pub fn nonce_recovery_attack_repeated(&self, msg: String) -> (BigUint, DsaSignature) {
        let mut k = BigUint::zero();
        let mut _m = Vec::new();
        let mut _r = Vec::new();
        let mut _s = Vec::new();
        msg.lines().for_each(|line| {
            let val: String = line.chars().skip(3).collect();
            if line.starts_with("m: ") {
                _m.push(BigUint::from_str(&val).unwrap());
            }
            if line.starts_with("r: ") {
                _r.push(BigUint::from_str(&val).unwrap());
            }
            if line.starts_with("s: ") {
                _s.push(BigUint::from_str(&val).unwrap());
            }
        });
        for i in (0.._m.len()).any(|i| {
            (i + 1.._m.len()).filter(|&j| _m[i] != _m[j]).any(|j| {
                let k =             
            })
        })
        
        (k, DsaSignature {r, s})
    }
}
