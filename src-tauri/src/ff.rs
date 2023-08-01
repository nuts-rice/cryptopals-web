pub mod FunkyFiniteFields {
    use num_bigint::BigUint;
    use subtle::{Choice, ConstantTimeEq};
    pub const BRANCH_SECRET: u64 = 1234567890123456;
    struct FieldElement {
        limbs: usize,
        order: BigUint,
        modulus: BigUint,
        a2: usize,
        a4: usize,
        a6: usize,
    }

    //conditional assignment
    //refer to
    //https://research.nccgroup.com/2022/06/15/public-report-threshold-ecdsa-cryptography-review/ and
    //https://github.com/dfinity/ic/commit/34703fad074f5bb53142b2cf5f569c5c66c6c3b1#diff-1b547352196f5d4ae84d7793a304d5d780d757dfd0959465c4e5fde996608a54

    //happy choice for conditionally assigning using subtle::choice and subtle::constanttimeeq
    pub fn assign_on_subtle(target: u64, _assign: &mut subtle::Choice) {
        for i in 0..=999 {
            *_assign &= BRANCH_SECRET.to_be_bytes()[i].ct_eq(&target.to_be_bytes()[i])
        }
    }

    //evil naughty choice for bad boys!
    pub fn assign_on_secret(target: u64, _assign: bool) {
        let mut cmp = 0;
        for i in 0..=999 {
            cmp |= BRANCH_SECRET.to_be_bytes()[i] ^ target.to_be_bytes()[i]
        }
    }

    // pub fn random_fe ()  -> FieldElement {
    //     let mut rng = rand::thread_rng();
    //     let mut buf = vec![0u8; ]
    // }
}
