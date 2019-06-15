use crate::proof::{Proof, ProofStep};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::{Debug, Error as FmtError, Formatter};

pub mod proof;

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

#[derive(Debug)]
pub struct Update<'a> {
    pub utreexo: &'a mut Utreexo,
    pub updated: HashMap<Hash, ProofStep>,
}

impl<'a> Update<'a> {
    pub fn prove(&self, leaf: &Hash) -> Proof {
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
    pub roots: Vec<Option<Hash>>,
}

impl Utreexo {
    pub fn new(capacity: usize) -> Self {
        Utreexo {
            roots: vec![None; capacity],
        }
    }

    fn hash_pair(&self, left: &Hash, right: &Hash) -> Hash {
        let concat = left
            .0
            .into_iter()
            .chain(right.0.into_iter())
            .map(|b| *b)
            .collect::<Vec<_>>();
        hash(&concat[..])
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
        if self.roots.len() < proof.steps.len() || self.roots.get(proof.steps.len()).is_none() {
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
                            if !self.roots[height]
                                .and_then(|h| Some(h == hash))
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
        let mut new_roots = Vec::new();

        for root in self.roots.iter() {
            let mut vec = Vec::<Hash>::new();
            if let Some(hash) = root {
                vec.push(*hash);
            }

            new_roots.push(vec);
        }

        let mut updated = HashMap::<Hash, ProofStep>::new();

        for d in deletions {
            self.delete(d, &mut new_roots)?;
        }

        if new_roots.is_empty() {
            new_roots.push(vec![]);
        }
        new_roots[0].extend_from_slice(insertions);

        for i in 0..new_roots.len() {
            while new_roots[i].len() > 1 {
                let a = new_roots[i][new_roots[i].len() - 2];
                let b = new_roots[i][new_roots[i].len() - 1];
                new_roots[i].pop();
                new_roots[i].pop();

                let hash = self.hash_pair(&a, &b);

                // Grow the accumulator
                if new_roots.len() <= i + 1 {
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

        // Check for accumulator overflow
        for roots in new_roots.iter() {
            if roots.len() > 1 {
                return Err(());
            }
        }

        for (i, bucket) in new_roots.into_iter().take(to_take).enumerate() {
            if self.roots.len() <= i {
                self.roots.push(None);
            }

            if bucket.is_empty() {
                self.roots[i] = None;
            } else {
                self.roots[i] = Some(bucket[0]);
            }
        }

        Ok(Update {
            utreexo: self,
            updated,
        })
    }

    pub fn verify(&self, proof: &Proof) -> bool {
        let n = proof.steps.len();
        if n >= self.roots.len() || self.roots[n].is_none() {
            return false;
        }

        let expected = self.roots[n];
        let mut h = proof.leaf;
        for s in proof.steps.iter() {
            let hp = if s.is_left {
                self.hash_pair(&s.hash, &h)
            } else {
                self.hash_pair(&h, &s.hash)
            };

            h = hp;
        }

        expected
            .and_then(|expected| Some(h == expected))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::hash;
    use crate::Utreexo;

    #[test]
    pub fn test_add_delete() {
        let mut acc = Utreexo::new(1); // Up to 3 elements

        let a = hash(b"a");
        let b = hash(b"b");
        let c = hash(b"c");
        let hashes = [a, b, c];

        let update = acc.update(&hashes[..], &[]).unwrap();

        let mut proofs = hashes.iter().map(|h| update.prove(h)).collect::<Vec<_>>();

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

    // Test for accumulator overflow is handled. Note that this test may be slow.
    #[test]
    pub fn test_add_exceed() {
        const MAX_CAPACITY: usize = 10; // Up to (2^capacity + 1) - 1 elements in accumulator

        for capacity in 1..MAX_CAPACITY {
            let mut acc = Utreexo::new(capacity);

            // Construct 2^(max_elements + 1) hashes from two bytes
            let max_elements = 2u16.pow((capacity as u32) + 1);
            let hashes = (0..max_elements)
                .into_iter()
                .map(|i| hash(&[(i << 8) as u8, (i & 0xff) as u8]))
                .collect::<Vec<_>>();

            // Should not insert due to accumulator overflow
            let update = acc.update(&hashes, &[]);
            assert!(update.is_err());

            // Should insert & verify with -1 element
            let update = acc
                .update(&hashes.iter().cloned().skip(1).collect::<Vec<_>>(), &[])
                .unwrap();

            let proofs = hashes
                .iter()
                .skip(1)
                .map(|h| update.prove(h))
                .collect::<Vec<_>>();
            for proof in proofs.iter() {
                assert!(acc.verify(&proof));
            }
        }
    }
}
