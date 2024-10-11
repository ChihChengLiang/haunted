use core::{fmt::Debug, ops::Deref};
use phantom_zone_evaluator::boolean::fhew::{self, param::I_4P_60, prelude::*};
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};

pub use fhew::prelude::HierarchicalSeedableRng;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PhantomParam {
    param: FhewBoolMpiParam,
    ring_packing_modulus: Option<Modulus>,
    ring_packing_auto_decomposition_param: DecompositionParam,
}

impl PhantomParam {
    pub const I_4P_60: Self = Self {
        param: I_4P_60,
        ring_packing_modulus: Some(Modulus::Prime(2305843009213554689)),
        ring_packing_auto_decomposition_param: DecompositionParam {
            log_base: 20,
            level: 1,
        },
    };
}

impl Deref for PhantomParam {
    type Target = FhewBoolMpiParam;

    fn deref(&self) -> &Self::Target {
        &self.param
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PhantomCrs(<StdRng as SeedableRng>::Seed);

impl PhantomCrs {
    pub const fn new(seed: <StdRng as SeedableRng>::Seed) -> Self {
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

type Ring = NativeRing;

type EvaluationRing = NoisyNativeRing;

type KeySwitchMod = NonNativePowerOfTwo;

type PackingRing = PrimeRing;

#[derive(Clone, Debug)]
pub struct PhantomOps {
    param: PhantomParam,
    ring: NativeRing,
    mod_ks: NonNativePowerOfTwo,
    ring_rp: PrimeRing,
}

impl PhantomOps {
    pub fn new(param: PhantomParam) -> Self {
        Self {
            param,
            ring: RingOps::new(param.modulus, param.ring_size),
            mod_ks: ModulusOps::new(param.lwe_modulus),
            ring_rp: RingOps::new(param.ring_packing_modulus.unwrap(), param.ring_size),
        }
    }

    pub fn param(&self) -> &PhantomParam {
        &self.param
    }

    pub fn fhew_param(&self) -> &FhewBoolParam {
        self.param()
    }

    pub fn ring_packing_param(&self) -> RingPackingParam {
        RingPackingParam {
            modulus: self
                .param()
                .ring_packing_modulus
                .unwrap_or_else(|| self.param().modulus),
            ring_size: self.param().ring_size,
            sk_distribution: self.param().sk_distribution,
            noise_distribution: self.param().noise_distribution,
            auto_decomposition_param: self.param().ring_packing_auto_decomposition_param,
        }
    }

    pub fn ring(&self) -> &Ring {
        &self.ring
    }

    pub fn mod_ks(&self) -> &KeySwitchMod {
        &self.mod_ks
    }

    pub fn ring_rp(&self) -> &PackingRing {
        &self.ring_rp
    }

    pub fn sk_gen(&self, mut rng: StdRng) -> PhantomSk {
        PhantomSk::sample(
            self.param().ring_size,
            self.param().sk_distribution,
            &mut rng,
        )
    }

    pub fn sk_ks_gen(&self, mut rng: StdRng) -> PhantomSkKs {
        PhantomSkKs::sample(
            self.param().lwe_dimension,
            self.param().lwe_sk_distribution,
            &mut rng,
        )
    }

    pub fn pk_share_gen(
        &self,
        crs: &PhantomCrs,
        sk: &PhantomSk,
        mut rng: StdRng,
    ) -> PhantomPkShare {
        let mut pk = PhantomPkShare::allocate(self.param().ring_size);
        pk_share_gen(
            self.ring(),
            &mut pk,
            self.param(),
            &crs.fhew(),
            sk,
            &mut rng,
        );
        pk
    }

    pub fn rp_key_share_gen(
        &self,
        crs: &PhantomCrs,
        sk: &PhantomSk,
        mut rng: StdRng,
    ) -> PhantomRpKeyShare {
        let mut rp_key = PhantomRpKeyShare::allocate(self.ring_packing_param());
        rp_key_share_gen(
            self.ring_rp(),
            &mut rp_key,
            &crs.ring_packing(),
            sk,
            &mut rng,
        );
        rp_key
    }

    pub fn bs_key_share_gen(
        &self,
        crs: &PhantomCrs,
        share_idx: usize,
        sk: &PhantomSk,
        pk: &PhantomPk,
        sk_ks: &PhantomSkKs,
        mut rng: StdRng,
    ) -> PhantomBsKeyShare {
        let mut bs_key_share = PhantomBsKeyShare::allocate(**self.param(), share_idx);
        bs_key_share_gen(
            self.ring(),
            self.mod_ks(),
            &mut bs_key_share,
            &crs.fhew(),
            sk,
            pk,
            sk_ks,
            &mut rng,
        );
        bs_key_share
    }

    pub fn batched_pk_encrypt(
        &self,
        pk: &PhantomPk,
        ms: impl IntoIterator<Item = bool>,
    ) -> PhantomBatchedCt {
        PhantomBatchedCt::pk_encrypt(
            self.fhew_param(),
            self.ring(),
            pk,
            ms,
            &mut LweRng::new(StdRng::from_entropy(), StdRng::from_entropy()),
        )
    }

    pub fn aggregate_rp_dec_shares<'a>(
        &self,
        ct: &PhantomPackedCt,
        dec_shares: impl IntoIterator<Item = &'a PhantomPackedCtDecShare>,
    ) -> Vec<bool> {
        ct.aggregate_decryption_shares(self.ring_rp(), dec_shares)
    }

    pub fn aggregate_pk_shares<'a>(
        &self,
        crs: &PhantomCrs,
        pk_shares: impl IntoIterator<Item = &'a PhantomPkShare>,
    ) -> PhantomPk {
        let mut pk = RlwePublicKey::allocate(self.fhew_param().ring_size);
        aggregate_pk_shares(self.ring(), &mut pk, &crs.fhew(), pk_shares);
        pk
    }

    pub fn aggregate_rp_key_shares<'a>(
        &self,
        crs: &PhantomCrs,
        rp_key_shares: impl IntoIterator<Item = &'a PhantomRpKeyShare>,
    ) -> PhantomRpKey {
        let mut rp_key = PhantomRpKey::allocate(self.ring_packing_param());
        aggregate_rp_key_shares(
            self.ring_rp(),
            &mut rp_key,
            &crs.ring_packing(),
            rp_key_shares,
        );
        rp_key
    }

    pub fn aggregate_bs_key_shares<'a>(
        &self,
        crs: &PhantomCrs,
        bs_key_shares: impl IntoIterator<Item = &'a PhantomBsKeyShare>,
    ) -> PhantomBsKey {
        let mut bs_key = PhantomBsKey::allocate(*self.fhew_param());
        aggregate_bs_key_shares(
            self.ring(),
            self.mod_ks(),
            &mut bs_key,
            &crs.fhew(),
            bs_key_shares,
        );
        bs_key
    }

    pub fn aggregate_rp_decryption_shares<'a>(
        &self,
        ct: &PhantomPackedCt,
        dec_shares: impl IntoIterator<Item = &'a PhantomPackedCtDecShare>,
    ) -> Vec<bool> {
        ct.aggregate_decryption_shares(self.ring_rp(), dec_shares)
    }

    pub fn prepare_rp_key(&self, rp_key: &PhantomRpKey) -> PhantomRpKeyPrep {
        let mut rp_key_prep =
            PhantomRpKeyPrep::allocate_eval(self.ring_packing_param(), self.ring_rp().eval_size());
        prepare_rp_key(self.ring_rp(), &mut rp_key_prep, rp_key);
        rp_key_prep
    }

    pub fn prepare_bs_key(&self, bs_key: &PhantomBsKey) -> PhantomBsKeyPrep {
        let ring: EvaluationRing = RingOps::new(self.param.modulus, self.param.ring_size);
        let mut bs_key_prep = PhantomBsKeyPrep::allocate_eval(**self.param, ring.eval_size());
        prepare_bs_key(&ring, &mut bs_key_prep, bs_key);
        bs_key_prep
    }

    pub fn evaluator(&self, bs_key: &PhantomBsKey) -> PhantomEvaluator {
        FhewBoolEvaluator::new(self.prepare_bs_key(bs_key))
    }

    pub fn pack<'a>(
        &self,
        rp_key: &PhantomRpKeyPrep,
        cts: impl IntoIterator<Item = &'a FhewBoolCiphertextOwned<Elem<Ring>>>,
    ) -> PhantomPackedCt {
        PhantomPackedCt::pack_ms(self.ring(), self.ring_rp(), rp_key, cts)
    }

    pub fn decrypt_share(&self, sk: &PhantomSk, ct: &PhantomPackedCt) -> PhantomPackedCtDecShare {
        ct.decrypt_share(
            &self.param,
            self.ring_rp(),
            sk,
            &mut LweRng::new(StdRng::from_entropy(), StdRng::from_entropy()),
        )
    }
}

pub type PhantomSk = RlweSecretKeyOwned<i64>;

pub type PhantomSkKs = LweSecretKeyOwned<i64>;

pub type PhantomPkShare = SeededRlwePublicKeyOwned<Elem<Ring>>;

pub type PhantomPk = RlwePublicKeyOwned<Elem<Ring>>;

pub type PhantomRpKeyShare = RingPackingKeyShareOwned<Elem<PackingRing>>;

pub type PhantomRpKey = RingPackingKeyOwned<Elem<PackingRing>>;

pub type PhantomRpKeyPrep = RingPackingKeyOwned<<PackingRing as RingOps>::EvalPrep>;

pub type PhantomBsKeyShare = FhewBoolMpiKeyShareOwned<Elem<Ring>, Elem<KeySwitchMod>>;

pub type PhantomBsKey = FhewBoolKeyOwned<Elem<Ring>, Elem<KeySwitchMod>>;

pub type PhantomBsKeyPrep =
    FhewBoolKeyOwned<<EvaluationRing as RingOps>::EvalPrep, Elem<KeySwitchMod>>;

pub type PhantomCt = FhewBoolCiphertextOwned<Elem<Ring>>;

pub type PhantomBatchedCt = FhewBoolBatchedCiphertextOwned<Elem<Ring>>;

pub type PhantomPackedCt = FhewBoolPackedCiphertextOwned<Elem<PackingRing>>;

pub type PhantomPackedCtDecShare = RlweDecryptionShareListOwned<Elem<Ring>>;

pub type PhantomEvaluator = FhewBoolEvaluator<EvaluationRing, KeySwitchMod>;

pub type PhantomBool<'a> = FheBool<'a, PhantomEvaluator>;
