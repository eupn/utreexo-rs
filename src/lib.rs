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
        let s = hex::encode(&self.0);

        // Used for testing
        match s.as_str() {
            "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb" => {
                write!(f, "Hash(A)")
            }
            "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d" => {
                write!(f, "Hash(B)")
            }
            "2e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6" => {
                write!(f, "Hash(C)")
            }
            "18ac3e7343f016890c510e93f935261169d9e3f565436429830faf0934f4f8e4" => {
                write!(f, "Hash(D)")
            }
            "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea" => {
                write!(f, "Hash(E)")
            }
            "252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111" => {
                write!(f, "Hash(F)")
            }

            "e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a" => {
                write!(f, "Hash(AB)")
            }
            "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b" => {
                write!(f, "Hash(CD)")
            }
            "04fa33f8b4bd3db545fa04cdd51b462509f611797c7bfe5c944ee2bb3b2ed908" => {
                write!(f, "Hash(EF)")
            }

            "5550fc504f47f6f1fe9e7eca497dbcec28bab880f68d6d9f914da898de7f0fac" => {
                write!(f, "Hash(ABCD)")
            }
            "2ed829ee84eb60c409670c40b8559502bca2339197b4795e2057a8bbac3a898c" => {
                write!(f, "Hash(EFCD)")
            }
            "23e314ee2b14a5895dc084ea6b175c4fd7792a2879c53e541595be0f675682db" => {
                write!(f, "Hash(EFAB)")
            }

            _ => write!(f, "Hash({})", s),
        }
    }
}

/// Updates made to the Utreexo accumulator, used to create proofs for inserted values.
#[derive(Debug)]
pub struct Update<'a> {
    pub utreexo: &'a mut Utreexo,
    pub updated: HashMap<Hash, ProofStep>,
}

impl<'a> Update<'a> {
    /// Create a proof for an element if that element was inserted during this Utreexo update.
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

/// A Utreexo accumulator. Holds array of Merkle forest roots.
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

            current_parent == expected
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Utreexo;
    use crate::{hash, Hash};

    #[test]
    pub fn test_add_delete() {
        let mut acc = Utreexo::new(3);

        let a = hash(b"a");
        let b = hash(b"b");
        let c = hash(b"c");
        let d = hash(b"d");
        let e = hash(b"e");
        let f = hash(b"f");
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
        fn insert_and_verify(capacity: usize, hashes: &[Hash]) -> bool {
            let mut acc = Utreexo::new(capacity);

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
                .map(|i| hash(&[(i << 8) as u8, (i & 0xff) as u8]))
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
