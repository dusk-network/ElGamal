// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use elgamal::{PrivateKey, PublicKey};

#[cfg(test)]
mod integrations {
    use super::*;

    #[test]
    // Test Encryption and decryption via a message
    // for the Cypher struct.
    fn test_cypher_encrypt_decrypt() {
        let private = PrivateKey::new(&mut rand::thread_rng());

        let public = PublicKey::from(private);

        let message = GENERATOR_EXTENDED * JubJubScalar::random(&mut rand::thread_rng());

        let y = JubJubScalar::random(&mut rand::thread_rng());
        let a = public.encrypt(message, y);
        let b = a.decrypt(private);

        assert_eq!(message, b);
    }

    #[test]
    fn test_wrong_message() {
        let private = PrivateKey::new(&mut rand::thread_rng());

        let public = PublicKey::from(private);

        let message = GENERATOR_EXTENDED * JubJubScalar::random(&mut rand::thread_rng());
        let m_1 = GENERATOR_EXTENDED * JubJubScalar::random(&mut rand::thread_rng());
        let y = JubJubScalar::random(&mut rand::thread_rng());
        let a = public.encrypt(message, y);
        let b = a.decrypt(private);

        assert_ne!(m_1, b);
    }
}
