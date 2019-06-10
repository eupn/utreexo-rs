fn hash(_bytes: &[u8]) -> Hash {
    // TODO: use real hash function
    Hash([0u8; 32])
}

#[derive(Debug, Copy, Clone)]
pub struct Hash(pub [u8; 32]);

pub const ZERO_HASH: Hash = Hash([0u8; 32]);

pub struct Utreexo {
    pub acc: Vec<Option<Hash>>,
}

impl Utreexo {
    pub fn new(capacity: usize) -> Self {
        Utreexo {
            acc: Vec::with_capacity(capacity),
        }
    }

    fn parent(&self, left: &Hash, right: &Hash) -> Hash {
        let append = left.0.into_iter().map(|e| *e).chain(right.0.into_iter().map(|e| *e)).collect::<Vec<_>>();
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