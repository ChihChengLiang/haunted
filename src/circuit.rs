use crate::phantom::PhantomBool;
use itertools::izip;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum CircuitId {
    // Demo circuit that computes `inputs[..inputs.len() / 2] ^ inputs[inputs.len() / 2..]`.
    Demo,
}

impl CircuitId {
    pub fn evaluate<'a>(&self, inputs: &[PhantomBool<'a>]) -> Vec<PhantomBool<'a>> {
        match self {
            Self::Demo => {
                let (l, r) = inputs.split_at(inputs.len() / 2);
                izip!(l, r).map(|(a, b)| a ^ b).collect()
            }
        }
    }
}
