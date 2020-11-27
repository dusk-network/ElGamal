// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod error;

use crate::error::Error;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use dusk_plonk::bls12_381::BlsScalar;
use dusk_plonk::jubjub::{JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
use rand::{CryptoRng, Rng};
use std::io;
use std::io::{Read, Write};

#[allow(non_snake_case)]
// This is the private key selected by the key generator
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivateKey(JubJubScalar);

impl PrivateKey {
    // This will create a new [`PrivateKey`] from a scalar
    // of the Field JubJubScalar.
    pub fn new<T>(rand: &mut T) -> PrivateKey
    where
        T: Rng + CryptoRng,
    {
        let fr = JubJubScalar::random(rand);

        PrivateKey(fr)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.0.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        match Option::from(JubJubScalar::from_bytes(bytes)) {
            Some(scalar) => Ok(PrivateKey(scalar)),
            _ => Err(Error::SerialisationError),
        }
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct PublicKey(JubJubExtended);

impl From<PrivateKey> for PublicKey {
    fn from(private: PrivateKey) -> Self {
        let point = GENERATOR_EXTENDED * private.0;

        PublicKey(point)
    }
}

impl PublicKey {
    // Encrypt a given message using a public key and random
    pub fn encrypt(self, message: JubJubExtended, secret: JubJubScalar) -> Cypher {
        let s = self.0 * secret;

        let gamma = GENERATOR_EXTENDED * secret;

        let delta = message + s;

        Cypher { gamma, delta }
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct Cypher {
    gamma: JubJubExtended,
    delta: JubJubExtended,
}

impl Cypher {
    // Decrypt a given cipher using a private key
    // this will return the message
    pub fn decrypt(self, private: PrivateKey) -> JubJubExtended {
        self.delta - self.gamma * private.0
    }

    // Returns Gamma from the Cypher struct
    pub fn gamma(self) -> JubJubExtended {
        self.gamma
    }

    // Returns Delta from the Cypher struct
    pub fn delta(self) -> JubJubExtended {
        self.delta
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&JubJubAffine::from(&self.gamma).to_bytes());
        buf[32..].copy_from_slice(&JubJubAffine::from(&self.delta).to_bytes());

        buf
    }

    #[allow(non_snake_case)]
    pub fn from_bytes(buf: [u8; 64]) -> Result<Cypher, Error> {
        let mut gamma_buf = [0u8; 32];
        gamma_buf.copy_from_slice(&buf[..32]);

        let mut delta_buf = [0u8; 32];
        delta_buf.copy_from_slice(&buf[32..]);

        let gamma_a = JubJubAffine::from_bytes(gamma_buf);
        if gamma_a.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidData);
        }

        let gamma = JubJubExtended::from(gamma_a.unwrap());

        let delta_a = JubJubAffine::from_bytes(delta_buf);
        if delta_a.is_none().unwrap_u8() == 1 {
            return Err(Error::InvalidData);
        }

        let delta = JubJubExtended::from(delta_a.unwrap());

        let cypher = Cypher {
            gamma: gamma,
            delta: delta,
        };
        Ok(cypher)
    }
}

impl Read for Cypher {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut n = 0;

        buf.chunks_mut(32)
            .next()
            .ok_or(Error::Generic)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += 32;
        buf.copy_from_slice(&JubJubAffine::from(self.gamma).to_bytes());

        buf.chunks_mut(32)
            .next()
            .ok_or(Error::Generic)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += 32;
        buf.copy_from_slice(&JubJubAffine::from(&self.delta).to_bytes());

        Ok(n)
    }
}

#[allow(non_snake_case)]
impl Write for Cypher {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut n = 0;

        let gamma_buf = buf
            .chunks(32)
            .next()
            .ok_or(Error::Generic)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += 32;
        let mut gamma_arr = [0u8; 32];
        gamma_arr.copy_from_slice(&gamma_buf);
        let gamma = JubJubAffine::from_bytes(gamma_arr);
        if gamma.is_none().unwrap_u8() == 1 {
            return Err(Error::Generic.into());
        }

        let delta_buf = buf
            .chunks(32)
            .next()
            .ok_or(Error::Generic)
            .map_err::<io::Error, _>(|e| e.into())?;
        n += 32;
        let mut delta_arr = [0u8; 32];
        delta_arr.copy_from_slice(&delta_buf);
        let delta = JubJubAffine::from_bytes(delta_arr);
        if delta.is_none().unwrap_u8() == 1 {
            return Err(Error::Generic.into());
        }

        self.gamma = JubJubExtended::from(gamma.unwrap());
        self.delta = JubJubExtended::from(delta.unwrap());

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Add for &Cypher {
    type Output = Cypher;

    fn add(self, other: &Cypher) -> Cypher {
        Cypher {
            gamma: self.gamma + other.gamma,
            delta: self.delta + other.delta,
        }
    }
}

impl Add for Cypher {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        &self + &other
    }
}

impl AddAssign for Cypher {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Sub for &Cypher {
    type Output = Cypher;

    fn sub(self, other: &Cypher) -> Cypher {
        Cypher {
            gamma: self.gamma - other.gamma,
            delta: self.delta - other.delta,
        }
    }
}

impl Sub for Cypher {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        &self - &other
    }
}

impl SubAssign for Cypher {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl Mul<&JubJubScalar> for &Cypher {
    type Output = Cypher;

    fn mul(self, rhs: &JubJubScalar) -> Cypher {
        Cypher {
            gamma: self.gamma * rhs,
            delta: self.delta * rhs,
        }
    }
}

impl Mul<JubJubScalar> for &Cypher {
    type Output = Cypher;

    fn mul(self, rhs: JubJubScalar) -> Cypher {
        self * &rhs
    }
}

impl MulAssign<JubJubScalar> for Cypher {
    fn mul_assign(&mut self, rhs: JubJubScalar) {
        *self = &*self * &rhs;
    }
}

impl<'b> MulAssign<&'b JubJubScalar> for Cypher {
    fn mul_assign(&mut self, rhs: &'b JubJubScalar) {
        *self = &*self * rhs;
    }
}
