use crate::{Hash, Update};

#[derive(Debug, Copy, Clone)]
pub struct ProofStep {
    pub hash: Hash,
    pub is_left: bool,
}

#[derive(Debug, Clone)]
pub struct Proof {
    pub steps: Vec<ProofStep>,
    pub leaf: Hash,
}

impl Proof {
    pub fn update(&mut self, update: &Update) -> Result<(), ()> {
        let mut h = self.leaf;
        for (i, curr_step) in self.steps.iter().enumerate() {
            let contains_root = update
                .utreexo
                .roots
                .get(i)
                .and_then(|roots| {
                    let root_equals = roots.and_then(|rh| Some(rh == h)).unwrap_or(false);
                    Some(root_equals)
                })
                .unwrap_or(false);

            if update.utreexo.roots.len() > i && contains_root {
                self.steps.truncate(i);
                return Ok(());
            }

            let step = if let Some(step) = update.updated.get(&h) {
                *step
            } else if i == self.steps.len() {
                break;
            } else {
                *curr_step
            };

            h = update.utreexo.parent(&h, &step);
        }

        Ok(())
    }
}
