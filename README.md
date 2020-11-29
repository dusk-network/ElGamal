
# EdDSA
Implementation of the ElGamal encryption scheme
for the JubJub curve group. This scheme is intended 
to encrypt two BlsScalars, as a message, inside the same 
JubJub Curve point. 
Implementation designed by the [dusk](https://dusk.network) 
team.

## About 
ElGamal encryption scheme is an asymmetric encryption algorithm,
which is defined over any cyclic group G.The alogrtihm allows 
two parties to share secret information without it being 
subject to eavesdropping by a third party. 

The implementation has been created using the
types from the JubJub library which is an embedded 
curve to BLS12-381. The implementation of the imported 
jubjub can 
be found [here](https://github.com/dusk-network/jubjub). 

For a reference to the algorithm, please see the 
[docs](https://app.gitbook.com/@dusk-network/s/specs/specifications/phoenix/elgamal-encryption).

**This structure of this library is as follows:** 

- Public Key Propogation by party A 
- Message Encryption by party B 
- Message Decryption by party A 

## Example 

#### Key Propogation 

1. Party A should use their private key, a, to generate a public Key A: `a · g = A` 

`g is a generator of the JubJub elliptic curve group, G` 


#### Encryption

1. Party B is given `(A, g, G)`

2. B selects a random scalar, named `secret`,  from the group and computes: `secret * g = γ` 

3. B encrypts their message, m, using the public key of A: `A * secret + m = δ`

4. B then publishes the cypher, `(γ, δ)`


#### Decryption

1. A uses their private key, to recover message `m` from the cypher via the following:

  `δ - γ · a = m`.

## Licensing
This code is licensed under Mozilla Public License Version 2.0 (MPL-2.0). 
Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for further info.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
