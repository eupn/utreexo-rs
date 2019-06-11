use sha2::{Sha256, Digest};
use std::io::Write;

fn hash(bytes: &[u8]) -> Hash {
    let mut sha = Sha256::new();
    sha.input(bytes);
    let res = sha.result();

    let mut bytes = [0u8; 32];
    res.to_vec().write(&mut bytes).unwrap();

    Hash(bytes)
}

#[derive(Debug, Copy, Clone)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn mini(&self) -> Minihash {
        self.into()
    }
}

pub const MINIHASH_LEN: usize = 12;

#[derive(Debug, Copy, Clone)]
pub struct Minihash(pub [u8; MINIHASH_LEN]);

impl From<&Hash> for Minihash {
    fn from(hash: &Hash) -> Self {
        let mut minihash = [0u8; MINIHASH_LEN];
        for (i, b) in hash.0.iter().enumerate().take(MINIHASH_LEN) {
            minihash[i] = *b;
        }

        Minihash(minihash)
    }
}

pub const ZERO_HASH: Hash = Hash([0u8; 32]);

pub struct Utreexo {
    pub acc: Vec<Option<Hash>>,
}

impl Utreexo {
    pub fn new(capacity: usize) -> Self {
        Utreexo {
            acc: vec![None; capacity]
        }
    }

    fn parent(&self, left: &Hash, right: &Hash) -> Hash {
        let append = left
            .0
            .into_iter()
            .map(|e| *e)
            .chain(right.0.into_iter().map(|e| *e))
            .collect::<Vec<_>>();
        hash(&append[..])
    }

    pub fn add_one(&mut self, l: &Hash) {
        let mut n = *l;
        let mut h = 0;
        let mut r = self.acc[h].clone();
        while let Some(hash) = &r {
            let parent = self.parent(&hash, &n);
            n = parent;
            self.acc[h] = None;
            h += 1;
            r = self.acc[h];
        }

        self.acc[h] = Some(n);
    }

    pub fn delete_one(&mut self, proof: &[Hash]) {
        let mut n = None;
        let mut h = 0;

        while h < proof.len() {
            let p = proof[h];
            if let Some(hash) = n {
                n = Some(self.parent(&p, &hash));
            } else if self.acc[h].is_none() {
                self.acc[h] = Some(p);
            } else {
                n = Some(self.parent(&p, &self.acc[h].unwrap_or(ZERO_HASH)));
            }

            h += 1;
        }

        self.acc[h] = n;
    }
}

#[cfg(test)]
mod tests {
    use crate::{Utreexo, MINIHASH_LEN};
    use crate::hash;

    #[test]
    pub fn test_minishash() {
        let hash = hash(b"test");
        let minihash = hash.mini();

        assert_eq!(hash.0[0..MINIHASH_LEN], minihash.0);
    }

    #[test]
    pub fn test_add() {
        let mut acc = Utreexo::new(10);

        acc.add_one(&hash(b"test"));
        acc.add_one(&hash(b"test2"));
        acc.add_one(&hash(b"test3"));

        println!("Acc: {:?}", acc.acc);
    }
}