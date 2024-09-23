use crate::types::ParamCRS;
use itertools::Itertools;
use phantom_zone_evaluator::boolean::fhew::prelude::*;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

pub(crate) struct Client<R: RingOps, M: ModulusOps> {
    param: FhewBoolMpiParam,
    crs: FhewBoolMpiCrs<StdRng>,
    share_idx: usize,
    sk_seed: <StdRng as SeedableRng>::Seed,
    pk: RlwePublicKeyOwned<R::Elem>,
    ring: R,
    mod_ks: M,
}

impl<R: RingOps, M: ModulusOps> Client<R, M> {
    pub(crate) fn new(
        param: FhewBoolMpiParam,
        crs: FhewBoolMpiCrs<StdRng>,
        share_idx: usize,
    ) -> Self {
        let mut sk_seed = <StdRng as SeedableRng>::Seed::default();
        StdRng::from_entropy().fill_bytes(sk_seed.as_mut());
        Self {
            param,
            crs,
            share_idx,
            sk_seed,
            pk: RlwePublicKey::allocate(param.ring_size),
            ring: RingOps::new(param.modulus, param.ring_size),
            mod_ks: M::new(param.lwe_modulus),
        }
    }

    pub(crate) fn sk(&self) -> RlweSecretKeyOwned<i64> {
        RlweSecretKey::sample(
            self.param.ring_size,
            self.param.sk_distribution,
            &mut StdRng::from_hierarchical_seed(self.sk_seed, &[0]),
        )
    }

    /// Key-Switched secret key
    pub(crate) fn sk_ks(&self) -> LweSecretKeyOwned<i64> {
        LweSecretKey::sample(
            self.param.lwe_dimension,
            self.param.lwe_sk_distribution,
            &mut StdRng::from_hierarchical_seed(self.sk_seed, &[1]),
        )
    }

    pub(crate) fn pk_share_gen(&self) -> Vec<u8> {
        let mut pk = SeededRlwePublicKey::allocate(self.param.ring_size);
        pk_share_gen(
            &self.ring,
            &mut pk,
            &self.param,
            &self.crs,
            &self.sk(),
            &mut StdRng::from_entropy(),
        );
        serialize_pk_share(&self.ring, &pk)
    }

    pub(crate) fn receive_pk(&mut self, pk: &[u8]) {
        self.pk = deserialize_pk(&self.ring, &pk);
    }

    pub(crate) fn bs_key_share_gen(&self) -> Vec<u8> {
        let mut bs_key_share = FhewBoolMpiKeyShare::allocate(self.param, self.share_idx);
        bs_key_share_gen(
            &self.ring,
            &self.mod_ks,
            &mut bs_key_share,
            &self.crs,
            &self.sk(),
            &self.pk,
            &self.sk_ks(),
            &mut StdRng::from_entropy(),
        );
        serialize_bs_key_share(&self.ring, &self.mod_ks, &bs_key_share)
    }

    pub(crate) fn pk_encrypt_bit(
        &self,
        m: impl IntoIterator<Item = bool>,
    ) -> Vec<u8> {
      let cts =  pk_encrypt_bit(&self.param, &self.ring, &self.pk, m);
      serialize_cts_bits(&self.ring, &cts)
    }

    pub(crate) fn pk_encrypt_u8(&self, m: u8) -> [FhewBoolCiphertextOwned<R::Elem>; 8] {
        pk_encrypt_u8(&self.param, &self.ring, &self.pk, m)
    }
    pub(crate) fn decrypt_share_u8(&self, ct: &[u8]) -> Vec<u8> {
        let ct = deserialize_cts_u8(&self.ring, &ct);
        let ds: [LweDecryptionShare<R::Elem>; 8] = ct.map(|ct| {
            ct.decrypt_share(
                &self.ring,
                self.sk().as_view(),
                self.param.noise_distribution,
                &mut StdLweRng::from_entropy(),
            )
        });
        serialize_decryption_share_u8::<R>(&ds)
    }
    pub(crate) fn decrypt_u8(&self, ct: &[u8], dec_shares: &[Vec<u8>]) -> u8 {
        let ct = deserialize_cts_u8(&self.ring, &ct);
        let dec_shares = dec_shares
            .iter()
            .map(|ds| deserialize_decryption_share_u8::<R>(ds))
            .collect_vec();
        aggregate_decryption_shares(&self.ring, ct, &dec_shares)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub(crate) struct Server<R: RingOps, M: ModulusOps> {
    param: FhewBoolMpiParam,
    crs: FhewBoolMpiCrs<StdRng>,
    pk: RlwePublicKeyOwned<R::Elem>,
    #[serde(rename = "bs_key")]
    evaluator: FhewBoolEvaluator<R, M>,
}

impl<R: RingOps, M: ModulusOps> Server<R, M> {
    pub(crate) fn new(param: FhewBoolMpiParam) -> Self {
        Self {
            param,
            crs: FhewBoolMpiCrs::sample(StdRng::from_entropy()),
            pk: RlwePublicKey::allocate(param.ring_size),
            evaluator: FhewBoolEvaluator::new(FhewBoolKey::allocate(*param)),
        }
    }

    pub(crate) fn get_param_crs(&self) -> ParamCRS {
        (self.param, self.crs)
    }

    fn ring(&self) -> &R {
        self.evaluator.ring()
    }

    fn mod_ks(&self) -> &M {
        self.evaluator.mod_ks()
    }

    pub(crate) fn aggregate_pk_shares(&mut self, pk_shares: &[SeededRlwePublicKeyOwned<R::Elem>]) {
        aggregate_pk_shares(self.evaluator.ring(), &mut self.pk, &self.crs, pk_shares);
    }

    pub(crate) fn aggregate_bs_key_shares<R2: RingOps<Elem = R::Elem>>(
        &mut self,
        bs_key_shares: &[FhewBoolMpiKeyShareOwned<R::Elem, M::Elem>],
    ) {
        let bs_key = {
            let ring = <R2 as RingOps>::new(self.param.modulus, self.param.ring_size);
            let mut bs_key = FhewBoolKey::allocate(*self.param);
            aggregate_bs_key_shares(&ring, self.mod_ks(), &mut bs_key, &self.crs, bs_key_shares);
            bs_key
        };
        let bs_key_prep = {
            let mut bs_key_prep = FhewBoolKey::allocate_eval(*self.param, self.ring().eval_size());
            prepare_bs_key(self.ring(), &mut bs_key_prep, &bs_key);
            bs_key_prep
        };
        self.evaluator = FhewBoolEvaluator::new(bs_key_prep);
    }

    pub(crate) fn pk_encrypt_bits(
        &self,
        m: impl IntoIterator<Item = bool>,
    ) -> Vec<FhewBoolCiphertextOwned<R::Elem>> {
        pk_encrypt_bit(&self.param, self.ring(), &self.pk, m)
    }

    pub(crate) fn pk_encrypt_u8(&self, m: u8) -> [FhewBoolCiphertextOwned<R::Elem>; 8] {
        pk_encrypt_u8(&self.param, self.ring(), &self.pk, m)
    }
}

fn pk_encrypt_u8<R: RingOps>(
    param: &FhewBoolParam,
    ring: &R,
    pk: &RlwePublicKeyOwned<R::Elem>,
    m: u8,
) -> [FhewBoolCiphertextOwned<R::Elem>; 8] {
    FhewBoolCiphertext::batched_pk_encrypt(
        param,
        ring,
        pk,
        (0..8).map(|idx| (m >> idx) & 1 == 1),
        &mut StdLweRng::from_entropy(),
    )
    .try_into()
    .unwrap()
}

fn pk_encrypt_bit<R: RingOps>(
    param: &FhewBoolParam,
    ring: &R,
    pk: &RlwePublicKeyOwned<R::Elem>,
    m: impl IntoIterator<Item = bool>,
) -> Vec<FhewBoolCiphertextOwned<R::Elem>> {
    FhewBoolCiphertext::batched_pk_encrypt(param, ring, pk, m, &mut StdLweRng::from_entropy())
}

fn aggregate_decryption_shares<R: RingOps>(
    ring: &R,
    ct: [FhewBoolCiphertextOwned<R::Elem>; 8],
    dec_shares: &[[LweDecryptionShare<R::Elem>; 8]],
) -> u8 {
    (0..8)
        .map(|idx| {
            let dec_shares = dec_shares.iter().map(|dec_shares| &dec_shares[idx]);
            ct[idx].aggregate_decryption_shares(ring, dec_shares)
        })
        .rev()
        .fold(0, |m, b| (m << 1) | b as u8)
}

fn serialize_pk_share<R: RingOps>(
    ring: &R,
    pk_share: &SeededRlwePublicKeyOwned<R::Elem>,
) -> Vec<u8> {
    bincode::serialize(&pk_share.compact(ring)).unwrap()
}

pub(crate) fn deserialize_pk_share<R: RingOps>(
    ring: &R,
    bytes: &[u8],
) -> SeededRlwePublicKeyOwned<R::Elem> {
    let pk_share_compact: SeededRlwePublicKey<Compact> = bincode::deserialize(bytes).unwrap();
    pk_share_compact.uncompact(ring)
}

pub(crate) fn serialize_pk<R: RingOps>(ring: &R, pk: &RlwePublicKeyOwned<R::Elem>) -> Vec<u8> {
    bincode::serialize(&pk.compact(ring)).unwrap()
}

fn deserialize_pk<R: RingOps>(ring: &R, bytes: &[u8]) -> RlwePublicKeyOwned<R::Elem> {
    let pk_compact: RlwePublicKey<Compact> = bincode::deserialize(bytes).unwrap();
    pk_compact.uncompact(ring)
}

fn serialize_bs_key_share<R: RingOps, M: ModulusOps>(
    ring: &R,
    mod_ks: &M,
    bs_key_share: &FhewBoolMpiKeyShareOwned<R::Elem, M::Elem>,
) -> Vec<u8> {
    bincode::serialize(&bs_key_share.compact(ring, mod_ks)).unwrap()
}

fn serialize_decryption_share_u8<R: RingOps>(share: &[LweDecryptionShare<R::Elem>; 8]) -> Vec<u8> {
    bincode::serialize(&share).unwrap()
}

fn serialize_decryption_share_bits<R: RingOps>(share: &[LweDecryptionShare<R::Elem>]) -> Vec<u8> {
    bincode::serialize(&share).unwrap()
}

fn deserialize_decryption_share_u8<R: RingOps>(share: &[u8]) -> [LweDecryptionShare<R::Elem>; 8] {
    bincode::deserialize(&share).unwrap()
}

fn deserialize_decryption_share_bits<R: RingOps>(share: &[u8]) -> Vec<LweDecryptionShare<R::Elem>> {
    bincode::deserialize(&share).unwrap()
}

fn deserialize_bs_key_share<R: RingOps, M: ModulusOps>(
    ring: &R,
    mod_ks: &M,
    bytes: &[u8],
) -> FhewBoolMpiKeyShareOwned<R::Elem, M::Elem> {
    let bs_key_share_compact: FhewBoolMpiKeyShareCompact = bincode::deserialize(bytes).unwrap();
    bs_key_share_compact.uncompact(ring, mod_ks)
}

fn serialize_cts_u8<R: RingOps>(ring: &R, cts: [FhewBoolCiphertextOwned<R::Elem>; 8]) -> Vec<u8> {
    bincode::serialize(&cts.map(|ct| ct.compact(ring))).unwrap()
}

fn serialize_cts_bits<R: RingOps>(ring: &R, cts: &[FhewBoolCiphertextOwned<R::Elem>]) -> Vec<u8> {
    bincode::serialize(&cts.iter().map(|ct| ct.compact(ring)).collect_vec()).unwrap()
}

fn deserialize_cts_u8<R: RingOps>(ring: &R, bytes: &[u8]) -> [FhewBoolCiphertextOwned<R::Elem>; 8] {
    let cts: [FhewBoolCiphertext<Compact>; 8] = bincode::deserialize(bytes).unwrap();
    cts.map(|ct| ct.uncompact(ring))
}

fn deserialize_cts_bits<R: RingOps>(
    ring: &R,
    bytes: &[u8],
) -> Vec<FhewBoolCiphertextOwned<R::Elem>> {
    let cts: Vec<FhewBoolCiphertext<Compact>> = bincode::deserialize(bytes).unwrap();
    cts.iter().map(|ct| ct.uncompact(ring)).collect_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{array::from_fn, num::Wrapping};
    use num_traits::NumOps;
    use phantom_zone_evaluator::boolean::{fhew::param::I_4P, FheBool};
    use rand::Rng;
    use std::ops::{BitAnd, BitOr, BitXor};

    fn function<T>(a: &T, b: &T, c: &T, d: &T, e: &T) -> T
    where
        T: for<'t> NumOps<&'t T, T>,
        for<'t> &'t T: NumOps<&'t T, T>,
    {
        (((a + b) - c) * d) % e
    }
    #[test]
    fn test_phantom() {
        let mut server = Server::<NoisyPrimeRing, NonNativePowerOfTwo>::new(I_4P);
        let mut clients = (0..server.param.total_shares)
            .map(|share_idx| {
                Client::<PrimeRing, NonNativePowerOfTwo>::new(server.param, server.crs, share_idx)
            })
            .collect_vec();

        // Round 1

        // Clients generate public key shares
        let pk_shares = clients
            .iter()
            .map(|client| client.pk_share_gen())
            .collect_vec();

        // Server aggregates public key shares
        server.aggregate_pk_shares(
            &pk_shares
                .into_iter()
                .map(|bytes| deserialize_pk_share(server.ring(), &bytes))
                .collect_vec(),
        );
        let pk = serialize_pk(server.ring(), &server.pk);

        // Round 2

        // Clients generate bootstrapping key shares
        let bs_key_shares = clients
            .iter_mut()
            .map(|client| {
                client.receive_pk(&pk);
                client.bs_key_share_gen()
            })
            .collect_vec();

        // Server aggregates bootstrapping key shares
        server.aggregate_bs_key_shares::<PrimeRing>(
            &bs_key_shares
                .into_iter()
                .map(|bytes| deserialize_bs_key_share(server.ring(), server.mod_ks(), &bytes))
                .collect_vec(),
        );

        // Server performs FHE evaluation
        let m = from_fn(|_| StdRng::from_entropy().gen());
        let g = {
            let [a, b, c, d, e] = &m.map(Wrapping);
            function(a, b, c, d, e).0
        };
        let ct_g = {
            let [a, b, c, d, e] =
                &m.map(|m| FheU8::from_cts(&server.evaluator, server.pk_encrypt_u8(m)));
            serialize_cts_u8(server.ring(), function(a, b, c, d, e).into_cts())
        };

        // Clients generate decryption share of evaluation output
        let ct_g_dec_shares = clients
            .iter()
            .map(|client| client.decrypt_share_u8(&ct_g))
            .collect_vec();

        // Aggregate decryption shares
        assert_eq!(g, clients[0].decrypt_u8(&ct_g, &ct_g_dec_shares));
    }
    trait BitOps<Rhs = Self, Output = Self>:
        BitAnd<Rhs, Output = Output> + BitOr<Rhs, Output = Output> + BitXor<Rhs, Output = Output>
    {
    }

    impl<T, Rhs, Output> BitOps<Rhs, Output> for T where
        T: BitAnd<Rhs, Output = Output>
            + BitOr<Rhs, Output = Output>
            + BitXor<Rhs, Output = Output>
    {
    }

    fn function_bit<T>(a: &T, b: &T, c: &T, d: &T) -> T
    where
        T: for<'t> BitOps<&'t T, T>,
        for<'t> &'t T: BitOps<&'t T, T>,
    {
        ((a | b) & c) ^ d
    }
    #[test]
    fn test_phantom_bits() {
        let mut server = Server::<NoisyPrimeRing, NonNativePowerOfTwo>::new(I_4P);
        let mut clients = (0..server.param.total_shares)
            .map(|share_idx| {
                Client::<PrimeRing, NonNativePowerOfTwo>::new(server.param, server.crs, share_idx)
            })
            .collect_vec();

        // Round 1

        // Clients generate public key shares
        let pk_shares = clients
            .iter()
            .map(|client| client.pk_share_gen())
            .collect_vec();

        // Server aggregates public key shares
        server.aggregate_pk_shares(
            &pk_shares
                .into_iter()
                .map(|bytes| deserialize_pk_share(server.ring(), &bytes))
                .collect_vec(),
        );
        let pk = serialize_pk(server.ring(), &server.pk);

        // Round 2

        // Clients generate bootstrapping key shares
        let bs_key_shares = clients
            .iter_mut()
            .map(|client| {
                client.receive_pk(&pk);
                client.bs_key_share_gen()
            })
            .collect_vec();

        // Server aggregates bootstrapping key shares
        server.aggregate_bs_key_shares::<PrimeRing>(
            &bs_key_shares
                .into_iter()
                .map(|bytes| deserialize_bs_key_share(server.ring(), server.mod_ks(), &bytes))
                .collect_vec(),
        );

        // Server performs FHE evaluation
        let m: [bool; 4] = from_fn(|_| StdRng::from_entropy().gen());
        let g = {
            let [a, b, c, d] = &m;
            function_bit(a, b, c, d)
        };
        let ct_g = {
            let bytes = clients[0].pk_encrypt_bit(m);
            let [a, b, c, d]: [FheBool<_>;4] = deserialize_cts_bits(server.ring(), &bytes).try_into().unwrap();
            serialize_cts_bits(server.ring(), function_bit(&a, &b, &c, &d).into_cts())
        };

        // Clients generate decryption share of evaluation output
        let ct_g_dec_shares = clients
            .iter()
            .map(|client| client.decrypt_share_u8(&ct_g))
            .collect_vec();

        // Aggregate decryption shares
        assert_eq!(g, clients[0].decrypt_u8(&ct_g, &ct_g_dec_shares));
    }
}
