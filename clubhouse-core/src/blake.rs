use orion::errors::UnknownCryptoError;
use orion::hazardous::hash::blake2::blake2b;

pub enum SmallBlakeHasher {
    /// Blake2b with `24` as `size`.
    Blake2b24,
    /// Blake2b with `32` as `size`.
    Blake2b32,
}

impl SmallBlakeHasher {
    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a digest selected by the given Blake2b variant.
    pub fn digest(&self, data: &[u8]) -> Result<blake2b::Digest, UnknownCryptoError> {
        let size: usize = match *self {
            SmallBlakeHasher::Blake2b24 => 24,
            SmallBlakeHasher::Blake2b32 => 32,
        };

        let mut state = blake2b::Blake2b::new(size)?;
        state.update(data)?;
        state.finalize()
    }

    #[must_use = "SECURITY WARNING: Ignoring a Result can have real security implications."]
    /// Return a `Blake2b` state selected by the given Blake2b variant.
    pub fn init(&self) -> Result<blake2b::Blake2b, UnknownCryptoError> {
        match *self {
            SmallBlakeHasher::Blake2b24 => blake2b::Blake2b::new(24),
            SmallBlakeHasher::Blake2b32 => blake2b::Blake2b::new(32),
        }
    }
}
