#![allow(clippy::type_complexity)]

use core::{fmt::Debug, ops::Deref};
use itertools::Itertools;
use phantom_zone_evaluator::boolean::fhew::prelude::*;
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::ops::{BitAnd, BitOr, BitXor};

pub trait PhantomOps: Debug {
    type Ring: RingOps;
    type EvaluationRing: RingOps<Elem = Elem<Self::Ring>>;
    type KeySwitchMod: ModulusOps;
    type PackingRing: RingOps;

    fn new(param: FhewBoolParam) -> Self;

    fn param(&self) -> &FhewBoolParam;

    fn ring_packing_param(&self) -> RingPackingParam {
        let param = self.param();
        RingPackingParam {
            modulus: self.ring_rp().modulus(),
            ring_size: param.ring_size,
            sk_distribution: param.sk_distribution,
            noise_distribution: param.noise_distribution,
            auto_decomposition_param: param.auto_decomposition_param,
        }
    }

    fn ring(&self) -> &Self::Ring;

    fn mod_ks(&self) -> &Self::KeySwitchMod;

    fn ring_rp(&self) -> &Self::PackingRing;

    /// Batched encrypt bits by public key.
    fn batched_pk_encrypt(
        &self,
        pk: &RlwePublicKeyOwned<Elem<Self::Ring>>,
        ms: impl IntoIterator<Item = bool>,
    ) -> FhewBoolBatchedCiphertextOwned<Elem<Self::Ring>> {
        FhewBoolBatchedCiphertextOwned::pk_encrypt(
            self.param(),
            self.ring(),
            pk,
            ms,
            &mut StdLweRng::from_entropy(),
        )
    }

    /// Pack LWE ciphertexts into RLWE ciphertexts (ring packing ciphertext).
    fn pack<'a>(
        &self,
        rp_key: &RingPackingKeyOwned<<Self::PackingRing as RingOps>::EvalPrep>,
        cts: impl IntoIterator<Item = &'a FhewBoolCiphertextOwned<Elem<Self::Ring>>>,
    ) -> FhewBoolPackedCiphertextOwned<Elem<Self::PackingRing>>;

    /// Aggregate decryption shares of ring packing ciphertext
    fn aggregate_rp_decryption_shares<'a>(
        &self,
        ct: &FhewBoolPackedCiphertextOwned<Elem<Self::PackingRing>>,
        dec_shares: impl IntoIterator<Item = &'a RlweDecryptionShareListOwned<Elem<Self::PackingRing>>>,
    ) -> Vec<bool> {
        ct.aggregate_decryption_shares(self.ring_rp(), dec_shares)
    }

    /// Serialize public key share
    fn serialize_pk_share(
        &self,
        pk_share: &SeededRlwePublicKeyOwned<Elem<Self::Ring>>,
    ) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&pk_share.compact(self.ring()))
    }

    /// Deserialize public key share
    fn deserialize_pk_share(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<SeededRlwePublicKeyOwned<Elem<Self::Ring>>> {
        let pk_share_compact: SeededRlwePublicKey<Compact> = bincode::deserialize(bytes)?;
        Ok(pk_share_compact.uncompact(self.ring()))
    }

    /// Serialize ring packing key share
    fn serialize_rp_key_share(
        &self,
        rp_key_share: &RingPackingKeyShareOwned<Elem<Self::Ring>>,
    ) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&rp_key_share.compact(self.ring()))
    }

    /// Deserialize ring packing key share
    fn deserialize_rp_key_share(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<RingPackingKeyShareOwned<Elem<Self::Ring>>> {
        let rp_key_share_compact: RingPackingKeyShareCompact = bincode::deserialize(bytes)?;
        Ok(rp_key_share_compact.uncompact(self.ring()))
    }

    /// Serialize bootstrapping key share
    fn serialize_bs_key_share(
        &self,
        bs_key_share: &FhewBoolMpiKeyShareOwned<Elem<Self::Ring>, Elem<Self::KeySwitchMod>>,
    ) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&bs_key_share.compact(self.ring(), self.mod_ks()))
    }

    /// Deserialize bootstrapping key share
    fn deserialize_bs_key_share(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<FhewBoolMpiKeyShareOwned<Elem<Self::Ring>, Elem<Self::KeySwitchMod>>> {
        let bs_key_share_compact: FhewBoolMpiKeyShareCompact = bincode::deserialize(bytes)?;
        Ok(bs_key_share_compact.uncompact(self.ring(), self.mod_ks()))
    }

    /// Serialize public key
    fn serialize_pk(&self, pk: &RlwePublicKeyOwned<Elem<Self::Ring>>) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&pk.compact(self.ring()))
    }

    /// Deserialize public key
    fn deserialize_pk(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<RlwePublicKeyOwned<Elem<Self::Ring>>> {
        let pk_compact: RlwePublicKey<Compact> = bincode::deserialize(bytes)?;
        Ok(pk_compact.uncompact(self.ring()))
    }

    /// Serialize ring packing key
    fn serialize_rp_key(
        &self,
        rp_key: &RingPackingKeyOwned<Elem<Self::PackingRing>>,
    ) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&rp_key.compact(self.ring_rp()))
    }

    /// Deserialize ring packing key
    fn deserialize_rp_key(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<RingPackingKeyOwned<Elem<Self::PackingRing>>> {
        let rp_key_compact: RingPackingKeyCompact = bincode::deserialize(bytes)?;
        Ok(rp_key_compact.uncompact(self.ring_rp()))
    }

    /// Serialize ring packing key
    fn serialize_bs_key(
        &self,
        bs_key: &FhewBoolKeyOwned<Elem<Self::EvaluationRing>, Elem<Self::KeySwitchMod>>,
    ) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&bs_key.compact(self.ring(), self.mod_ks()))
    }

    /// Deserialize ring packing key
    fn deserialize_bs_key(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<FhewBoolKeyOwned<Elem<Self::EvaluationRing>, Elem<Self::KeySwitchMod>>>
    {
        let bs_key_compact: FhewBoolKeyCompact = bincode::deserialize(bytes)?;
        Ok(bs_key_compact.uncompact(self.ring(), self.mod_ks()))
    }

    /// Serialize batched ciphertext
    fn serialize_batched_ct(
        &self,
        ct: &FhewBoolBatchedCiphertextOwned<Elem<Self::Ring>>,
    ) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&ct.compact(self.ring()))
    }

    /// Deserialize batched ciphertext
    fn deserialize_batched_ct(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<FhewBoolBatchedCiphertextOwned<Elem<Self::Ring>>> {
        let ct_compact: FhewBoolBatchedCiphertext<Compact> = bincode::deserialize(bytes)?;
        Ok(ct_compact.uncompact(self.ring()))
    }

    /// Serialize ring packing ciphertext
    fn serialize_rp_ct(
        &self,
        ct: &FhewBoolPackedCiphertextOwned<Elem<Self::PackingRing>>,
    ) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&ct.compact(self.ring_rp()))
    }

    /// Deserialize ring packing ciphertext
    fn deserialize_rp_ct(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<FhewBoolPackedCiphertextOwned<Elem<Self::PackingRing>>> {
        let ct_compact: FhewBoolPackedCiphertext<Compact> = bincode::deserialize(bytes)?;
        Ok(ct_compact.uncompact(self.ring_rp()))
    }

    /// Serialize decryption share of ring packing ciphertext
    fn serialize_rp_dec_share(
        &self,
        dec_share: &RlweDecryptionShareListOwned<Elem<Self::PackingRing>>,
    ) -> bincode::Result<Vec<u8>> {
        bincode::serialize(&dec_share.compact(self.ring_rp()))
    }

    /// Deserialize decryption share of ring packing ciphertext
    fn deserialize_rp_dec_share(
        &self,
        bytes: &[u8],
    ) -> bincode::Result<RlweDecryptionShareListOwned<Elem<Self::PackingRing>>> {
        let dec_share_compact: RlweDecryptionShareList<Compact> = bincode::deserialize(bytes)?;
        Ok(dec_share_compact.uncompact(self.ring_rp()))
    }
}

#[derive(Clone, Debug)]
pub struct PhantomNativeOps {
    param: FhewBoolParam,
    ring: NativeRing,
    mod_ks: NonNativePowerOfTwo,
    ring_rp: PrimeRing,
}

impl PhantomOps for PhantomNativeOps {
    type Ring = NativeRing;
    type EvaluationRing = NoisyNativeRing;
    type KeySwitchMod = NonNativePowerOfTwo;
    type PackingRing = PrimeRing;

    fn new(param: FhewBoolParam) -> Self {
        Self {
            param,
            ring: RingOps::new(param.modulus, param.ring_size),
            mod_ks: ModulusOps::new(param.lwe_modulus),
            ring_rp: RingOps::new(Modulus::Prime(2305843009213554689), param.ring_size),
        }
    }

    fn param(&self) -> &FhewBoolParam {
        &self.param
    }

    fn ring(&self) -> &Self::Ring {
        &self.ring
    }

    fn mod_ks(&self) -> &Self::KeySwitchMod {
        &self.mod_ks
    }

    fn ring_rp(&self) -> &Self::PackingRing {
        &self.ring_rp
    }

    fn pack<'a>(
        &self,
        rp_key: &RingPackingKeyOwned<<Self::PackingRing as RingOps>::EvalPrep>,
        cts: impl IntoIterator<Item = &'a FhewBoolCiphertextOwned<Elem<Self::Ring>>>,
    ) -> FhewBoolPackedCiphertextOwned<Elem<Self::PackingRing>> {
        FhewBoolPackedCiphertext::pack_ms(self.ring(), self.ring_rp(), rp_key, cts)
    }
}

#[derive(Clone, Debug)]
pub struct PhantomPrimeOps {
    param: FhewBoolParam,
    ring: PrimeRing,
    mod_ks: NonNativePowerOfTwo,
}

impl PhantomOps for PhantomPrimeOps {
    type Ring = PrimeRing;
    type EvaluationRing = NoisyPrimeRing;
    type KeySwitchMod = NonNativePowerOfTwo;
    type PackingRing = PrimeRing;

    fn new(param: FhewBoolParam) -> Self {
        Self {
            param,
            ring: RingOps::new(param.modulus, param.ring_size),
            mod_ks: ModulusOps::new(param.lwe_modulus),
        }
    }

    fn param(&self) -> &FhewBoolParam {
        &self.param
    }

    fn ring(&self) -> &Self::Ring {
        &self.ring
    }

    fn mod_ks(&self) -> &Self::KeySwitchMod {
        &self.mod_ks
    }

    fn ring_rp(&self) -> &Self::PackingRing {
        &self.ring
    }

    fn pack<'a>(
        &self,
        rp_key: &RingPackingKeyOwned<<Self::PackingRing as RingOps>::EvalPrep>,
        cts: impl IntoIterator<Item = &'a FhewBoolCiphertextOwned<Elem<Self::Ring>>>,
    ) -> FhewBoolPackedCiphertextOwned<Elem<Self::PackingRing>> {
        FhewBoolPackedCiphertext::pack(self.ring_rp(), rp_key, cts)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PhantomCrs(<StdRng as SeedableRng>::Seed);

impl PhantomCrs {
    pub fn new(seed: <StdRng as SeedableRng>::Seed) -> Self {
        Self(seed)
    }

    pub fn from_entropy() -> Self {
        Self::new(thread_rng().gen())
    }

    fn fhew(&self) -> FhewBoolMpiCrs<StdRng> {
        FhewBoolMpiCrs::new(StdRng::from_hierarchical_seed(self.0, &[0]).gen())
    }

    fn ring_packing(&self) -> RingPackingCrs<StdRng> {
        RingPackingCrs::new(StdRng::from_hierarchical_seed(self.0, &[1]).gen())
    }
}

#[derive(Clone, Debug)]
pub struct PhantomClient<O: PhantomOps> {
    param: FhewBoolMpiParam,
    crs: PhantomCrs,
    ops: O,
    share_idx: usize,
    seed: <StdRng as SeedableRng>::Seed,
    pk: Option<RlwePublicKeyOwned<Elem<O::Ring>>>,
}

impl<O: PhantomOps> Deref for PhantomClient<O> {
    type Target = O;

    fn deref(&self) -> &Self::Target {
        &self.ops
    }
}

impl<O: PhantomOps> PhantomClient<O> {
    pub fn new(
        param: FhewBoolMpiParam,
        crs: PhantomCrs,
        share_idx: usize,
        seed: <StdRng as SeedableRng>::Seed,
        pk_bytes: Option<&[u8]>,
    ) -> bincode::Result<Self> {
        let mut client = Self {
            param,
            crs,
            ops: O::new(*param),
            share_idx,
            seed,
            pk: None,
        };
        if let Some(pk_bytes) = pk_bytes {
            client.with_pk(client.deserialize_pk(pk_bytes)?);
        }
        Ok(client)
    }

    /// Returns seed.
    pub fn seed(&self) -> <StdRng as SeedableRng>::Seed {
        self.seed
    }

    fn sk(&self) -> RlweSecretKeyOwned<i64> {
        RlweSecretKey::sample(
            self.param.ring_size,
            self.param.sk_distribution,
            &mut StdRng::from_hierarchical_seed(self.seed, &[0, 0]),
        )
    }

    fn sk_ks(&self) -> LweSecretKeyOwned<i64> {
        LweSecretKey::sample(
            self.param.lwe_dimension,
            self.param.lwe_sk_distribution,
            &mut StdRng::from_hierarchical_seed(self.seed, &[0, 1]),
        )
    }

    /// Returns aggregated public key.
    ///
    /// # Panics
    ///
    /// Panics if `pk` is not given in [`Self::new`], or [`Self::with_pk`] is
    /// not invoked yet.
    pub fn pk(&self) -> &RlwePublicKeyOwned<Elem<O::Ring>> {
        self.pk.as_ref().unwrap()
    }

    /// Generate public key share.
    pub fn pk_share_gen(&self) -> SeededRlwePublicKeyOwned<Elem<O::Ring>> {
        let mut pk = SeededRlwePublicKey::allocate(self.param.ring_size);
        pk_share_gen(
            self.ring(),
            &mut pk,
            &self.param,
            &self.crs.fhew(),
            &self.sk(),
            &mut StdRng::from_hierarchical_seed(self.seed, &[1, 0]),
        );
        pk
    }

    /// Generate ring packing share.
    pub fn rp_key_share_gen(&self) -> RingPackingKeyShareOwned<Elem<O::PackingRing>> {
        let mut rp_key = RingPackingKeyShareOwned::allocate(self.ring_packing_param());
        rp_key_share_gen(
            self.ring_rp(),
            &mut rp_key,
            &self.crs.ring_packing(),
            &self.sk(),
            &mut StdRng::from_hierarchical_seed(self.seed, &[1, 1]),
        );
        rp_key
    }

    /// Set aggregated public key.
    pub fn with_pk(&mut self, pk: RlwePublicKeyOwned<Elem<O::Ring>>) {
        self.pk = Some(pk.cloned());
    }

    /// Generate bootstrapping key share.
    ///
    /// # Panics
    ///
    /// Panics if `pk` is not given in [`Self::new`], or [`Self::with_pk`] is
    /// not invoked yet.
    pub fn bs_key_share_gen(
        &self,
    ) -> FhewBoolMpiKeyShareOwned<Elem<O::Ring>, Elem<O::KeySwitchMod>> {
        let mut bs_key_share = FhewBoolMpiKeyShareOwned::allocate(self.param, self.share_idx);
        bs_key_share_gen(
            self.ring(),
            self.mod_ks(),
            &mut bs_key_share,
            &self.crs.fhew(),
            &self.sk(),
            self.pk(),
            &self.sk_ks(),
            &mut StdRng::from_hierarchical_seed(self.seed, &[1, 2]),
        );
        bs_key_share
    }

    /// Batched encrypt bits by public key.
    ///
    /// # Panics
    ///
    /// Panics if `pk` is not given in [`Self::new`], or [`Self::with_pk`] is
    /// not invoked yet.
    pub fn batched_pk_encrypt(
        &self,
        ms: impl IntoIterator<Item = bool>,
    ) -> FhewBoolBatchedCiphertextOwned<Elem<O::Ring>> {
        self.ops.batched_pk_encrypt(self.pk(), ms)
    }

    /// Generate decryption share of ring packing ciphertext.
    pub fn rp_decrypt_share(
        &self,
        ct: &FhewBoolPackedCiphertextOwned<Elem<O::PackingRing>>,
    ) -> RlweDecryptionShareListOwned<Elem<O::PackingRing>> {
        ct.decrypt_share(
            &self.param,
            self.ring_rp(),
            self.sk().as_view(),
            &mut StdLweRng::from_entropy(),
        )
    }

    /// Serialize aggregated public key.
    pub fn serialize_pk(&self) -> bincode::Result<Vec<u8>> {
        self.ops.serialize_pk(self.pk())
    }
}

#[derive(Clone, Debug)]
pub struct PhantomServer<O: PhantomOps> {
    param: FhewBoolMpiParam,
    crs: PhantomCrs,
    ops: O,
    pk: Option<RlwePublicKeyOwned<Elem<O::Ring>>>,
    rp_key: Option<RingPackingKeyOwned<Elem<O::PackingRing>>>,
    rp_key_prep: Option<RingPackingKeyOwned<<O::PackingRing as RingOps>::EvalPrep>>,
    bs_key: Option<FhewBoolKeyOwned<Elem<O::Ring>, Elem<O::KeySwitchMod>>>,
    evaluator: Option<FhewBoolEvaluator<O::EvaluationRing, O::KeySwitchMod>>,
}

impl<O: PhantomOps> Deref for PhantomServer<O> {
    type Target = O;

    fn deref(&self) -> &Self::Target {
        &self.ops
    }
}

impl<O: PhantomOps> PhantomServer<O> {
    /// Returns server.
    pub fn new(
        param: FhewBoolMpiParam,
        crs: PhantomCrs,
        pk_bytes: Option<&[u8]>,
        rp_key_bytes: Option<&[u8]>,
        bs_key_bytes: Option<&[u8]>,
    ) -> bincode::Result<Self> {
        let mut server = Self {
            param,
            crs,
            ops: O::new(*param),
            pk: None,
            rp_key: None,
            rp_key_prep: None,
            bs_key: None,
            evaluator: None,
        };
        if let Some(pk_bytes) = pk_bytes {
            server.with_pk(server.deserialize_pk(pk_bytes)?);
        }
        if let Some(rp_key_bytes) = rp_key_bytes {
            server.with_rp_key(server.deserialize_rp_key(rp_key_bytes)?);
        }
        if let Some(bs_key_bytes) = bs_key_bytes {
            server.with_bs_key(server.deserialize_bs_key(bs_key_bytes)?);
        }
        Ok(server)
    }

    /// Returns parameter.
    pub fn param(&self) -> &FhewBoolMpiParam {
        &self.param
    }

    /// Returns common reference string.
    pub fn crs(&self) -> &PhantomCrs {
        &self.crs
    }

    /// Returns aggregated public key.
    ///
    /// # Panics
    ///
    /// Panics if `pk` is not given in [`Self::new`], or
    /// [`Self::aggregate_pk_shares`] and [`Self::with_pk`] are not invoked yet.
    pub fn pk(&self) -> &RlwePublicKeyOwned<Elem<O::Ring>> {
        self.pk.as_ref().unwrap()
    }

    /// Returns aggregated ring packing key.
    ///
    /// # Panics
    ///
    /// Panics if `rp_key` is not given in [`Self::new`], or
    /// [`Self::aggregate_rp_key_shares`] and [`Self::with_rp_key`] is not
    /// invoked yet.
    pub fn rp_key(&self) -> &RingPackingKeyOwned<Elem<O::PackingRing>> {
        self.rp_key.as_ref().unwrap()
    }

    fn rp_key_prep(&self) -> &RingPackingKeyOwned<<O::PackingRing as RingOps>::EvalPrep> {
        self.rp_key_prep.as_ref().unwrap()
    }

    /// Returns evaluator.
    ///
    /// # Panics
    ///
    /// Panics if `bs_key` is not given in [`Self::new`], or
    /// [`Self::aggregate_bs_key_shares`] and [`Self::with_bs_key`] is not
    /// invoked yet.
    pub fn evaluator(&self) -> &FhewBoolEvaluator<O::EvaluationRing, O::KeySwitchMod> {
        self.evaluator.as_ref().unwrap()
    }

    /// Returns aggregated bootstrapping key.
    ///
    /// # Panics
    ///
    /// Panics if `bs_key` is not given in [`Self::new`], or
    /// [`Self::aggregate_bs_key_shares`] and [`Self::with_bs_key`] is not
    /// invoked yet.
    pub fn bs_key(&self) -> &FhewBoolKeyOwned<Elem<O::EvaluationRing>, Elem<O::KeySwitchMod>> {
        self.bs_key.as_ref().unwrap()
    }

    /// Set aggregated public key.
    pub fn with_pk(&mut self, pk: RlwePublicKeyOwned<Elem<O::Ring>>) {
        self.pk = Some(pk)
    }

    /// Set aggregated ring packing key.
    pub fn with_rp_key(&mut self, rp_key: RingPackingKeyOwned<Elem<O::PackingRing>>) {
        let mut rp_key_prep = RingPackingKeyOwned::allocate_eval(
            self.ring_packing_param(),
            self.ring_rp().eval_size(),
        );
        prepare_rp_key(self.ring_rp(), &mut rp_key_prep, &rp_key);
        self.rp_key = Some(rp_key);
        self.rp_key_prep = Some(rp_key_prep);
    }

    /// Set aggregated bootstrapping key.
    pub fn with_bs_key(
        &mut self,
        bs_key: FhewBoolKeyOwned<Elem<O::EvaluationRing>, Elem<O::KeySwitchMod>>,
    ) {
        let bs_key_prep = {
            let ring: O::EvaluationRing = RingOps::new(self.param.modulus, self.param.ring_size);
            let mut bs_key_prep = FhewBoolKeyOwned::allocate_eval(*self.param, ring.eval_size());
            prepare_bs_key(&ring, &mut bs_key_prep, &bs_key);
            bs_key_prep
        };
        self.bs_key = Some(bs_key);
        self.evaluator = Some(FhewBoolEvaluator::new(bs_key_prep));
    }

    /// Aggregate public key shares and set it as aggregated public key.
    pub fn aggregate_pk_shares(&mut self, pk_shares: &[SeededRlwePublicKeyOwned<Elem<O::Ring>>]) {
        let crs = self.crs.fhew();
        let mut pk = RlwePublicKey::allocate(self.param.ring_size);
        aggregate_pk_shares(self.ring(), &mut pk, &crs, pk_shares);
        self.with_pk(pk);
    }

    /// Aggregate ring packing key shares and set it as aggregated ring packing key.
    pub fn aggregate_rp_key_shares(
        &mut self,
        rp_key_shares: &[RingPackingKeyShareOwned<Elem<O::PackingRing>>],
    ) {
        let crs = self.crs.ring_packing();
        let mut rp_key = RingPackingKeyOwned::allocate(self.ring_packing_param());
        aggregate_rp_key_shares(self.ring_rp(), &mut rp_key, &crs, rp_key_shares);
        self.with_rp_key(rp_key);
    }

    /// Aggregate bootstrapping key shares and set it as aggregated bootstrapping key.
    pub fn aggregate_bs_key_shares(
        &mut self,
        bs_key_shares: &[FhewBoolMpiKeyShareOwned<Elem<O::Ring>, Elem<O::KeySwitchMod>>],
    ) {
        let crs = self.crs.fhew();
        let bs_key = {
            let mut bs_key = FhewBoolKeyOwned::allocate(*self.param);
            aggregate_bs_key_shares(self.ring(), self.mod_ks(), &mut bs_key, &crs, bs_key_shares);
            bs_key
        };
        self.with_bs_key(bs_key);
    }

    /// Wrap batched ciphertext into [`Vec`] of [`FheBool`] for FHE evaluation.
    pub fn wrap_batched_ct(
        &self,
        ct: &FhewBoolBatchedCiphertextOwned<Elem<O::Ring>>,
    ) -> Vec<FheBool<FhewBoolEvaluator<O::EvaluationRing, O::KeySwitchMod>>> {
        ct.extract_all(self.ring())
            .into_iter()
            .map(|ct| FheBool::new(self.evaluator(), ct))
            .collect_vec()
    }

    /// Serialize aggregated public key.
    pub fn serialize_pk(&self) -> bincode::Result<Vec<u8>> {
        self.ops.serialize_pk(self.pk())
    }

    /// Serialize aggregated ring packing key.
    pub fn serialize_rp_key(&self) -> bincode::Result<Vec<u8>> {
        self.ops.serialize_rp_key(self.rp_key())
    }

    /// Serialize aggregated bootstrapping key.
    pub fn serialize_bs_key(&self) -> bincode::Result<Vec<u8>> {
        self.ops.serialize_bs_key(self.bs_key())
    }
}

impl PhantomServer<PhantomNativeOps> {
    /// Pack LWE ciphertexts into RLWE ciphertexts (ring packing ciphertext).
    pub fn pack<'a>(
        &self,
        cts: impl IntoIterator<
            Item = &'a FhewBoolCiphertextOwned<Elem<<PhantomNativeOps as PhantomOps>::Ring>>,
        >,
    ) -> FhewBoolPackedCiphertextOwned<Elem<<PhantomNativeOps as PhantomOps>::PackingRing>> {
        self.ops.pack(self.rp_key_prep(), cts)
    }
}

impl PhantomServer<PhantomPrimeOps> {
    /// Pack LWE ciphertexts into RLWE ciphertexts (ring packing ciphertext).
    pub fn pack<'a>(
        &self,
        cts: impl IntoIterator<
            Item = &'a FhewBoolCiphertextOwned<Elem<<PhantomPrimeOps as PhantomOps>::Ring>>,
        >,
    ) -> FhewBoolPackedCiphertextOwned<Elem<<PhantomPrimeOps as PhantomOps>::PackingRing>> {
        self.ops.pack(self.rp_key_prep(), cts)
    }
}

pub(crate) trait BitOps<Rhs = Self, Output = Self>:
    BitAnd<Rhs, Output = Output> + BitOr<Rhs, Output = Output> + BitXor<Rhs, Output = Output>
{
}

impl<T, Rhs, Output> BitOps<Rhs, Output> for T where
    T: BitAnd<Rhs, Output = Output> + BitOr<Rhs, Output = Output> + BitXor<Rhs, Output = Output>
{
}

pub(crate) fn function_bit<T>(a: &T, b: &T, c: &T, d: &T) -> T
where
    T: for<'t> BitOps<&'t T, T>,
    for<'t> &'t T: BitOps<&'t T, T>,
{
    ((a | b) & c) ^ d
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::array::from_fn;
    use itertools::{izip, Itertools};
    use phantom_zone_evaluator::boolean::{dev::MockBoolEvaluator, fhew::param::I_4P};
    use rand::Rng;
    use std::iter::repeat_with;

    fn function<'a, E: BoolEvaluator>(
        a: &[FheBool<'a, E>],
        b: &[FheBool<'a, E>],
        c: &[FheBool<'a, E>],
        d: &[FheBool<'a, E>],
    ) -> Vec<FheBool<'a, E>> {
        a.iter()
            .zip(b)
            .zip(c)
            .zip(d)
            .map(|(((a, b), c), d)| a ^ b ^ c ^ d)
            .collect()
    }

    #[test]
    fn test_phantom_bits() {
        let crs = PhantomCrs::from_entropy();
        let param = I_4P;
        let mut server =
            PhantomServer::<PhantomPrimeOps>::new(param, crs, None, None, None).unwrap();
        let mut clients = (0..param.total_shares)
            .map(|share_idx| {
                let seed = StdRng::from_entropy().gen();
                PhantomClient::<PhantomPrimeOps>::new(param, crs, share_idx, seed, None).unwrap()
            })
            .collect_vec();

        // Key generation round 1.

        let (pk_shares, rp_key_shares) = {
            let pk_shares = clients
                .iter()
                .map(|client| client.serialize_pk_share(&client.pk_share_gen()).unwrap())
                .collect_vec();
            let rp_key_shares = clients
                .iter()
                .map(|client| {
                    client
                        .serialize_rp_key_share(&client.rp_key_share_gen())
                        .unwrap()
                })
                .collect_vec();
            (pk_shares, rp_key_shares)
        };

        let pk = {
            server.aggregate_pk_shares(
                &pk_shares
                    .into_iter()
                    .map(|bytes| server.deserialize_pk_share(&bytes).unwrap())
                    .collect_vec(),
            );
            server.aggregate_rp_key_shares(
                &rp_key_shares
                    .into_iter()
                    .map(|bytes| server.deserialize_rp_key_share(&bytes).unwrap())
                    .collect_vec(),
            );
            server.serialize_pk().unwrap()
        };

        // Key generation round 2.

        let bs_key_shares = clients
            .iter_mut()
            .map(|client| {
                client.with_pk(client.deserialize_pk(&pk).unwrap());
                client
                    .serialize_bs_key_share(&client.bs_key_share_gen())
                    .unwrap()
            })
            .collect_vec();

        server.aggregate_bs_key_shares(
            &bs_key_shares
                .into_iter()
                .map(|bytes| server.deserialize_bs_key_share(&bytes).unwrap())
                .collect_vec(),
        );

        // FHE evaluation.

        let ms: [Vec<bool>; 4] = {
            let mut rng = StdRng::from_entropy();
            let n = 10;
            from_fn(|_| repeat_with(|| rng.gen()).take(n).collect())
        };
        let out = {
            let [a, b, c, d] = &ms
                .clone()
                .map(|m| m.into_iter().map(|m| m.into()).collect_vec());
            function::<MockBoolEvaluator>(a, b, c, d)
                .into_iter()
                .map(FheBool::into_ct)
                .collect_vec()
        };

        // Run FHE evaluation.

        let run = |server: &PhantomServer<PhantomPrimeOps>,
                   clients: &[PhantomClient<PhantomPrimeOps>]| {
            let cts = {
                from_fn(|i| {
                    let ct = clients[i].batched_pk_encrypt(ms[i].clone());
                    clients[i].serialize_batched_ct(&ct).unwrap()
                })
            };

            let ct_out = {
                let [a, b, c, d] = &cts.map(|bytes| {
                    let ct = server.deserialize_batched_ct(&bytes).unwrap();
                    server.wrap_batched_ct(&ct)
                });
                function(a, b, c, d)
                    .into_iter()
                    .map(FheBool::into_ct)
                    .collect_vec()
            };

            let rp_ct_out = server.serialize_rp_ct(&server.pack(&ct_out)).unwrap();

            let rp_ct_out_dec_shares = clients
                .iter()
                .map(|client| {
                    let dec_share =
                        client.rp_decrypt_share(&client.deserialize_rp_ct(&rp_ct_out).unwrap());
                    client.serialize_rp_dec_share(&dec_share).unwrap()
                })
                .collect_vec();

            assert_eq!(
                out.to_vec(),
                clients[0].aggregate_rp_decryption_shares(
                    &clients[0].deserialize_rp_ct(&rp_ct_out).unwrap(),
                    &rp_ct_out_dec_shares
                        .iter()
                        .map(|dec_share| clients[0].deserialize_rp_dec_share(dec_share).unwrap())
                        .collect_vec(),
                )
            );
        };

        run(&server, &clients);

        // Store aggregated keys and restart server.

        let pk_bytes = server.serialize_pk().unwrap();
        let rp_key_bytes = server.serialize_rp_key().unwrap();
        let bs_key_bytes = server.serialize_bs_key().unwrap();
        let server = PhantomServer::<PhantomPrimeOps>::new(
            param,
            crs,
            Some(&pk_bytes),
            Some(&rp_key_bytes),
            Some(&bs_key_bytes),
        )
        .unwrap();

        // Store seed and restart clients.

        let pk_bytes = clients[0].serialize_pk().unwrap();
        let seeds = clients.iter().map(|client| client.seed()).collect_vec();
        let clients = izip!(0.., seeds)
            .map(|(share_idx, seed)| {
                PhantomClient::<PhantomPrimeOps>::new(param, crs, share_idx, seed, Some(&pk_bytes))
                    .unwrap()
            })
            .collect_vec();

        // Run FHE evaluation again.

        run(&server, &clients);
    }
}
