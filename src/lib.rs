use crate::proof::{Proof, ProofStep};
use std::collections::HashMap;
pub use ring::digest::{Algorithm, Context, Digest};

pub mod proof;

fn hash(algo: &'static Algorithm, bytes: &[u8]) -> Digest {
    let mut ctx = Context::new(algo);
    ctx.update(bytes);
    ctx.finish()
}

/// Updates made to the Utreexo accumulator, used to create proofs for inserted values.
#[derive(Debug)]
pub struct Update<'a> {
    pub utreexo: &'a mut Utreexo,
    pub updated: HashMap<Vec<u8>, ProofStep>,
}

impl<'a> Update<'a> {
    /// Create a proof for an element if that element was inserted during this Utreexo update.
    pub fn prove(&self, leaf: &Digest) -> Proof {
        let mut proof = Proof {
            steps: vec![],
            leaf: *leaf,
        };

        let mut item = *leaf;
        while let Some(s) = self.updated.get(item.as_ref()) {
            proof.steps.push(*s);
            item = self.utreexo.parent(&item, &s);
        }

        proof
    }
}

/// A Utreexo accumulator. Holds array of Merkle forest roots.
#[derive(Debug, Clone)]
pub struct Utreexo {
    pub roots: Vec<Option<Digest>>,
    hasher: &'static Algorithm,
}

impl Utreexo {
    pub fn new(hasher: &'static Algorithm, capacity: usize) -> Self {
        Utreexo {
            roots: vec![None; capacity],
            hasher
        }
    }

    fn hash_pair(&self, left: &Digest, right: &Digest) -> Digest {
        let concat = left
            .as_ref()
            .into_iter()
            .chain(right.as_ref().into_iter())
            .map(|b| *b)
            .collect::<Vec<_>>();
        hash(self.hasher, &concat[..])
    }

    fn parent(&self, h: &Digest, step: &ProofStep) -> Digest {
        if step.is_left {
            self.hash_pair(&step.hash, &h)
        } else {
            self.hash_pair(&h, &step.hash)
        }
    }

    fn find_root(&self, root: &Digest, roots: &[Digest]) -> (usize, bool) {
        for (i, r) in roots.iter().enumerate() {
            if root.as_ref() == r.as_ref() {
                return (i, true);
            }
        }

        (0, false)
    }

    fn delete(&self, proof: &Proof, new_roots: &mut Vec<Vec<Digest>>) -> Result<(), ()> {
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
                                .and_then(|h| Some(h.as_ref() == hash.as_ref()))
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
        insertions: &[Digest],
        deletions: &[Proof],
    ) -> Result<Update<'a>, ()> {
        let mut new_roots = Vec::new();

        for root in self.roots.iter() {
            let mut vec = Vec::<Digest>::new();
            if let Some(hash) = root {
                vec.push(*hash);
            }

            new_roots.push(vec);
        }

        let mut updated = HashMap::<Vec<u8>, ProofStep>::new();

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
                    a.as_ref().to_vec(),
                    ProofStep {
                        hash: b,
                        is_left: false,
                    },
                );
                updated.insert(
                    b.as_ref().to_vec(),
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

        // Apply new roots to the accumulator
        self.roots.truncate(to_take);
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
        if n >= self.roots.len() {
            return false;
        }

        let expected = self.roots[n];
        if let Some(expected) = expected {
            let mut current_parent = proof.leaf;
            for s in proof.steps.iter() {
                current_parent = if s.is_left {
                    self.hash_pair(&s.hash, &current_parent)
                } else {
                    self.hash_pair(&current_parent, &s.hash)
                };
            }

            current_parent.as_ref() == expected.as_ref()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Utreexo;
    use crate::hash;
    use ring::digest::{SHA256, Digest, Algorithm};

    #[test]
    pub fn test_add_delete() {
        static ALGO: &'static Algorithm = &SHA256;

        let mut acc = Utreexo::new(ALGO, 3);

        let a = hash(ALGO, b"a");
        let b = hash(ALGO, b"b");
        let c = hash(ALGO, b"c");
        let d = hash(ALGO, b"d");
        let e = hash(ALGO, b"e");
        let f = hash(ALGO, b"f");
        let hashes = [a, b, c, d, e, f];

        let update = acc.update(&hashes[..], &[]).unwrap();

        let mut proofs = hashes.iter().map(|h| update.prove(h)).collect::<Vec<_>>();

        for proof in proofs.iter() {
            assert!(acc.verify(proof));
        }

        let update = acc.update(&[], &proofs[0..1]).unwrap();
        for proof in &mut proofs {
            proof.update(&update).unwrap();
        }

        for proof in &proofs[1..] {
            assert!(acc.verify(&proof));
        }
    }

    // Test for accumulator overflow is handled. Note that this test may be slow.
    #[test]
    pub fn test_add_exceed() {
        static ALGO: &'static Algorithm = &SHA256;

        fn insert_and_verify(capacity: usize, hashes: &[Digest]) -> bool {
            let mut acc = Utreexo::new(ALGO, capacity);

            let update = acc.update(&hashes, &[]);
            if let Ok(u) = update {
                let proofs = hashes.iter().map(|h| u.prove(h)).collect::<Vec<_>>();
                for proof in proofs.iter() {
                    if !acc.verify(&proof) {
                        return false;
                    }
                }

                true
            } else {
                false
            }
        }

        const MAX_CAPACITY: usize = 10; // Up to 2^capacity elements in accumulator

        for capacity in 1..MAX_CAPACITY {
            // Construct 2^(max_elements + 1) hashes from two bytes
            let max_elements = 2u16.pow((capacity as u32) + 1);
            let hashes = (0..max_elements)
                .into_iter()
                .map(|i| hash(ALGO, &[(i << 8) as u8, (i & 0xff) as u8]))
                .collect::<Vec<_>>();

            // Insert elements without overflow
            for cap in 0..capacity {
                assert!(insert_and_verify(capacity, &hashes[..cap]));
            }

            // Should not insert due to accumulator overflow
            assert!(!insert_and_verify(capacity, &hashes[..]));

            // Should insert & verify with one element skipped
            assert!(insert_and_verify(capacity, &hashes[1..]));
        }
    }
}
