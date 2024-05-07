use core::fmt;
use ethers::core::k256::ecdsa::digest::FixedOutput;
use ethers::core::k256::ecdsa::signature::hazmat::PrehashSigner;
use ethers::core::k256::ecdsa::signature::{DigestSigner, PrehashSignature};
use ethers::core::k256::ecdsa::{recoverable, signature, Error, Signature};
use ethers::core::k256::elliptic_curve::consts::U32;
use ethers::core::k256::sha2::Digest;
use ethers_core::utils::{hex, keccak256};
use rand::rngs::OsRng;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::fmt::Debug;
use std::str::FromStr;
use ethers::prelude::Address;

#[derive(Clone)]
pub struct SigningKey {
    secret_key: SecretKey,

    public_key: PublicKey,
}

impl SigningKey {
    pub fn random() -> Self {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        Self {
            secret_key,
            public_key,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let secret_key =
            SecretKey::from_slice(bytes).map_err(|err| Error::from_source(Box::new(err)))?;
        Ok(secret_key.into())
    }

    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret_key.secret_bytes()
    }
    
    pub fn address(&self) -> Address {
        let public_key = self.public_key.serialize_uncompressed();
        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);
        Address::from_slice(&hash[12..])
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(msg).unwrap();
        secp.sign_ecdsa(&message, &self.secret_key)
            .serialize_compact()
    }

    pub fn sign_recoverable(&self, msg: &[u8]) -> (secp256k1::ecdsa::RecoveryId, [u8; 64]) {
        let secp = Secp256k1::new();
        let message = Message::from_digest_slice(msg).unwrap();
        secp.sign_ecdsa_recoverable(&message, &self.secret_key)
            .serialize_compact()
    }
}

impl AsRef<PublicKey> for SigningKey {
    fn as_ref(&self) -> &PublicKey {
        &self.public_key
    }
}

impl<S> signature::Signer<S> for SigningKey
where
    S: PrehashSignature,
    Self: DigestSigner<S::Digest, S>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<S, Error> {
        self.try_sign_digest(Digest::new_with_prefix(msg))
    }
}

impl<D> DigestSigner<D, Signature> for SigningKey
where
    D: Digest + FixedOutput<OutputSize = U32>,
{
    fn try_sign_digest(&self, msg_digest: D) -> signature::Result<Signature> {
        self.sign_prehash(&msg_digest.finalize_fixed())
    }
}

impl<D> DigestSigner<D, recoverable::Signature> for SigningKey
where
    D: Digest + FixedOutput<OutputSize = U32>,
{
    fn try_sign_digest(&self, msg_digest: D) -> signature::Result<recoverable::Signature> {
        self.sign_prehash(&msg_digest.finalize_fixed())
    }
}

impl PrehashSigner<Signature> for SigningKey {
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<Signature> {
        let prehash = <[u8; 32]>::try_from(prehash).map_err(|_| Error::new())?;

        let sig = self.sign(&prehash);
        sig.as_slice().try_into()
    }
}

impl PrehashSigner<recoverable::Signature> for SigningKey {
    fn sign_prehash(&self, prehash: &[u8]) -> signature::Result<recoverable::Signature> {
        // Ethereum signatures use SHA-256 for RFC6979, even if the message
        // has been hashed with Keccak256
        let (recid, sig) = self.sign_recoverable(&prehash);
        let signature: Signature = sig.as_slice().try_into()?;
        recoverable::Signature::new(&signature, recoverable::Id::new(recid.to_i32() as u8)?)
    }
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

impl Eq for SigningKey {}

impl PartialEq for SigningKey {
    fn eq(&self, other: &SigningKey) -> bool {
        self.secret_key == other.secret_key
    }
}

impl From<SecretKey> for SigningKey {
    fn from(secret_key: SecretKey) -> SigningKey {
        Self::from(&secret_key)
    }
}

impl From<&SecretKey> for SigningKey {
    fn from(secret_key: &SecretKey) -> SigningKey {
        let secp = Secp256k1::new();
        let public_key = secret_key.public_key(&secp);
        Self {
            secret_key: secret_key.clone(),
            public_key,
        }
    }
}

impl From<SigningKey> for SecretKey {
    fn from(signing_key: SigningKey) -> SecretKey {
        signing_key.secret_key
    }
}

impl From<&SigningKey> for SecretKey {
    fn from(signing_key: &SigningKey) -> SecretKey {
        signing_key.secret_key.clone()
    }
}

impl FromStr for SigningKey {
    type Err = Error;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        let src = hex::decode(src).map_err(|err| Error::from_source(Box::new(err)))?;
        let sk = SigningKey::from_bytes(&src)?;
        Ok(sk.into())
    }
}
