// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
/// Standard error for the interface
pub enum Error {
    /// Cryptographic invalidity
    #[error("Generic Error in Encryption scheme")]
    Generic,

    /// Invalid data as an output
    #[error("Invalid data given for encryption scheme")]
    InvalidData,

    /// Invalid byte coversions
    #[error("Byte serialisation performed incorrectly")]
    SerialisationError,
}

impl Error {
    /// Return a generic error from any type. Represents a cryptographic mistake
    pub fn generic<T>(_e: T) -> Error {
        Error::Generic
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        match self {
            _ => io::Error::new(io::ErrorKind::Other, format!("{}", self)),
        }
    }
}
