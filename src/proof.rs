use crate::{Hash, Update};

/// Defines a single step of Merkle Proof of inclusion.
#[derive(Debug, Copy, Clone)]
pub struct ProofStep {
    pub hash: Hash,
    pub is_left: bool,
}

/// Defines the Merkle Proof of inclusion for a specific element in the Utreexo accumulator.
#[derive(Debug, Clone)]
pub struct Proof {
    pub steps: Vec<ProofStep>,
    pub leaf: Hash,
}

impl Proof {
    /// Updates proof when accumulator state changes. Change is reflected via `Update` structure.
    pub fn update(&mut self, update: &Update) -> Result<(), ()> {
        let mut h = self.leaf;
        for i in 0..=self.steps.len() {
            if update.utreexo.roots.len() > i
                && update
                    .utreexo
                    .roots
                    .get(i)
                    .and_then(|root| Some(root.and_then(|rh| Some(rh == h)).unwrap_or(false)))
                    .unwrap_or(false)
            {
                self.steps.truncate(i);
                return Ok(());
            }

            let step = if let Some(step) = update.updated.get(&h) {
                self.steps.truncate(i);
                self.steps.push(*step);

                *step
            } else if i == self.steps.len() {
                break;
            } else {
                self.steps[i]
            };

            h = update.utreexo.parent(&h, &step);
        }

        Ok(())
    }
}
