use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::{Debug, Error as FmtError, Formatter};

fn hash(bytes: &[u8]) -> Hash {
    let mut sha = Sha256::new();
    sha.input(bytes);
    let res = sha.result();
    let mut res_bytes = [0u8; 32];
    res_bytes.copy_from_slice(res.as_slice());

    Hash(res_bytes)
}

#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct Hash(pub [u8; 32]);

impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        write!(f, "Hash({})", hex::encode(&self.0))
    }
}

pub const ZERO_HASH: Hash = Hash([0u8; 32]);

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
            if update.utreexo.acc.len() > i
                && update.utreexo.acc.get(i)
                .and_then(|roots| Some(roots.get(0)
                    .and_then(|rh| Some(*rh == h)).unwrap_or(false)))
                .unwrap_or(false) {
                self.steps.truncate(i);
                return Ok(())
            }

            let step = if let Some(step) = update.updated.get(&h) {
                *step
            } else if i == self.steps.len() {
                break
            } else {
                *curr_step
            };

            h = update.utreexo.parent(&h, &step);
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Update<'a> {
    pub utreexo: &'a mut Utreexo,
    pub updated: HashMap<Hash, ProofStep>,
}

impl<'a> Update<'a> {
    pub fn proof(&self, leaf: &Hash) -> Proof {
        let mut proof = Proof {
            steps: vec![],
            leaf: *leaf,
        };

        let mut item = *leaf;
        while let Some(s) = self.updated.get(&item) {
            proof.steps.push(*s);
            item = self.utreexo.parent(&item, &s);
        }

        proof
    }
}

#[derive(Debug, Clone)]
pub struct Utreexo {
    pub acc: Vec<Vec<Hash>>,
}

impl Utreexo {
    pub fn new(capacity: usize) -> Self {
        Utreexo {
            acc: vec![vec![]; capacity],
        }
    }

    fn hash_pair(&self, left: &Hash, right: &Hash) -> Hash {
        let append = left
            .0
            .into_iter()
            .map(|e| *e)
            .chain(right.0.into_iter().map(|e| *e))
            .collect::<Vec<_>>();
        hash(&append[..])
    }

    fn parent(&self, h: &Hash, step: &ProofStep) -> Hash {
        if step.is_left {
            self.hash_pair(&step.hash, &h)
        } else {
            self.hash_pair(&h, &step.hash)
        }
    }

    fn find_root(&self, root: &Hash, roots: &[Hash]) -> (usize, bool) {
        for (i, r) in roots.iter().enumerate() {
            if root == r {
                return (i, true);
            }
        }

        (0, false)
    }

    fn delete(&self, proof: &Proof, new_roots: &mut Vec<Vec<Hash>>) -> Result<(), ()> {
        if self.acc.len() < proof.steps.len() || self.acc.get(proof.steps.len()).is_none() {
            return Err(());
        }

        let mut height = 0;
        let mut hash = proof.leaf;
        let mut s;

        loop {
            if height < new_roots.len() {
                let (index, ok) = self.find_root(&hash, &new_roots[height]);
                if ok {
                    // Remove hash from new_roots
                    new_roots[height].remove(index);

                    loop {
                        if height >= proof.steps.len() {
                            if !self.acc[height]
                                .get(0)
                                .and_then(|h| Some(*h == hash))
                                .unwrap_or(false)
                            {
                                return Err(());
                            }

                            return Ok(());
                        }

                        s = proof.steps[height];
                        hash = self.parent(&hash, &s);
                        height += 1;
                    }
                }
            }

            if height >= proof.steps.len() {
                return Err(());
            }

            while height > new_roots.len() {
                new_roots.push(vec![]);
            }

            s = proof.steps[height];
            new_roots[height].push(s.hash);
            hash = self.parent(&hash, &s);
            height += 1;
        }
    }

    pub fn update<'a>(
        &'a mut self,
        insertions: &[Hash],
        deletions: &[Proof],
    ) -> Result<Update<'a>, ()> {
        let mut new_roots = vec![Vec::<Hash>::new(); self.acc.len()];

        for (i, root) in self.acc.iter().enumerate() {
            new_roots[i] = root.clone();
        }

        let mut updated = HashMap::<Hash, ProofStep>::new();

        for d in deletions {
            self.delete(d, &mut new_roots)?;
        }

        if new_roots.is_empty() {
            new_roots.push(vec![]);
        }
        new_roots[0].extend(insertions.iter().map(|h| *h));

        for i in 0..new_roots.len() {
            while new_roots[i].len() > 1 {
                let a = new_roots[i][new_roots[i].len() - 2];
                let b = new_roots[i][new_roots[i].len() - 1];

                new_roots[i].pop();
                new_roots[i].pop();

                let hash = self.hash_pair(&a, &b);
                if new_roots.len() < i + 1 {
                    new_roots.push(vec![]);
                }

                new_roots[i + 1].push(hash);
                updated.insert(
                    a,
                    ProofStep {
                        hash: b,
                        is_left: false,
                    },
                );
                updated.insert(
                    b,
                    ProofStep {
                        hash: a,
                        is_left: true,
                    },
                );
            }
        }

        let cut_off = new_roots
            .iter()
            .rev()
            .take_while(|roots| roots.is_empty())
            .count();
        let to_take = new_roots.len() - cut_off;

        for (i, roots) in new_roots.into_iter().take(to_take).enumerate() {
            if self.acc.len() <= i {
                self.acc.push(vec![]);
            }

            if roots.is_empty() {
                self.acc[i] = vec![];
            } else {
                self.acc[i] = roots;
            }
        }

        Ok(Update {
            utreexo: self,
            updated,
        })
    }

    pub fn verify(&self, proof: &Proof) -> bool {
        let n = proof.steps.len();
        if n >= self.acc.len() || self.acc[n].is_empty() {
            return false;
        }

        let expected = self.acc[n][0];
        let mut h = proof.leaf;
        for s in proof.steps.iter() {
            let hp = if s.is_left {
                self.hash_pair(&s.hash, &h)
            } else {
                self.hash_pair(&h, &s.hash)
            };

            h = hp;
        }

        h == expected
    }
}

#[cfg(test)]
mod tests {
    use crate::hash;
    use crate::Utreexo;

    #[test]
    pub fn test_add_delete() {
        let mut acc = Utreexo::new(10);

        let a = hash(b"a");
        let b = hash(b"b");
        let c = hash(b"c");
        let hashes = [a, b, c];

        let update = acc.update(&hashes[..], &[]).unwrap();

        println!("Update: {:#?}", update);

        let mut proofs = hashes.iter().map(|h| update.proof(h)).collect::<Vec<_>>();

        println!("Proofs: {:#?}", proofs);

        for proof in proofs.iter() {
            assert!(acc.verify(proof));
        }

        let update = acc.update(&[], &[proofs[0].clone()]).unwrap();
        for proof in &mut proofs {
            proof.update(&update).unwrap();
        }

        for proof in proofs.iter().skip(1) {
            assert!(acc.verify(&proof));
        }
    }
}
