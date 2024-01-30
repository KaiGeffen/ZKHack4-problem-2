use ark_bls12_381::{g2::Config, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, Field};

use ark_serialize::{CanonicalDeserialize, Read};

use prompt::{puzzle, welcome};

use sha2::Sha256;
use std::fs::File;
use std::io::Cursor;
use std::ops::{Mul, Neg};

use ark_std::{rand::SeedableRng, UniformRand, Zero};

// Derive a point for the proof-of-knowledge for a given input
// This implementation uses a constant seed
fn derive_point_for_pok(i: usize) -> G2Affine {
    let rng = &mut ark_std::rand::rngs::StdRng::seed_from_u64(20399u64);
    G2Affine::rand(rng).mul(Fr::from(i as u64 + 1)).into()
}

// Generate a proof for the given secret key & i input
#[allow(dead_code)]
fn pok_prove(sk: Fr, i: usize) -> G2Affine {
    // Get the point for given input, multiply by given secret key, then convert:
    // G2Affine::from(result)
    derive_point_for_pok(i).mul(sk).into()
}

// Verify the given proof (public key, input, proof)
fn pok_verify(pk: G1Affine, i: usize, proof: G2Affine) {
    // e(pk, point) * e(G, proof)
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[derive_point_for_pok(i).neg(), proof]
    )
    .is_zero());
}

// Get the hasher used
fn hasher() -> MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>> {
    let wb_to_curve_hasher =
        MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>>::new(
            // Sick reference
            &[1, 3, 3, 7],
        )
        .unwrap();
    wb_to_curve_hasher
}

// Get the bls signature for the given secret key, msg pair
#[allow(dead_code)]
fn bls_sign(sk: Fr, msg: &[u8]) -> G2Affine {
    hasher().hash(msg).unwrap().mul(sk).into_affine()
}

// Verify the signature for given message + public key
fn bls_verify(pk: G1Affine, sig: G2Affine, msg: &[u8]) {
    // This takes G1 x G2 -> GT for each of the 1st elements and 2nd elements of the slices
    assert!(Bls12_381::multi_pairing(
        &[pk, G1Affine::generator()],
        &[hasher().hash(msg).unwrap().neg(), sig]
    )
    .is_zero());
}

// Read data from a given file
fn from_file<T: CanonicalDeserialize>(path: &str) -> T {
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    T::deserialize_uncompressed_unchecked(Cursor::new(&buffer)).unwrap()
}

fn main() {    
    welcome();
    puzzle(PUZZLE_DESCRIPTION);

    // Read the list of public keys (G1)
    // G1 refers to the elliptic curve of the form y**2 = x**3 + b (Depending on the curve)
    // G2 is the projective group
    // In this implementation, the first value is the key and the second is the proof for that key
    let public_keys: Vec<(G1Affine, G2Affine)> = from_file("public_keys.bin");

    // Verify the pok of each of the public keys
    public_keys
        // Iterator of the list
        .iter()
        // Enumerate that iterator (Return the tuple (i, val) )
        .enumerate()
        // For each of those pairs, proof-of-knowledge verify the key, it's index in the list of keys, and the associated proof
        .for_each(|(i, (pk, proof))| {
            pok_verify(*pk, i, *proof)
        });

    // The index fo the new key (End of the list of public keys)
    let new_key_index = public_keys.len();
    // The message that we're signing
    let message = b"KaiGeffen";

    /* Enter solution here */

    // The new key I'm adding to the BLS
    // Decide on a key such that adding it to the aggregate makes the aggregate into what I want
    let new_key = public_keys
        // Iterator over the public keys
        .iter()
        // Fold the new key plus all of the other keys
        .fold(G1Projective::from(G1Affine::zero()), |acc, (pk, _)|acc - pk)
        // Transform into affine representation
        .into_affine();

    // Take the proof for the first block (Block 0)
    // let proof_0 = public_keys[0].1;
    // let proof_n = public_keys[new_key_index - 1].1;
    // It was generated as sk * rng * (index + 1)
    // so if we multiply by our new index+1 we get the proof we want
    // let new_proof = proof_0.add(proof_n).into_affine();
    // proof_0.mul(Fr::from(new_key_index as u64 + 1)).into();

    // n! where n is the index of the new block (9)
    let factorial: u64 = 362880;
    let factorial_in_field: Fr = Fr::from(factorial);
    // The factorial's inverse in the field
    let inverse = factorial_in_field.inverse().unwrap();
    //47219887007697480994944254261702310610499426305610458197155785386193864019011

    let new_proof = public_keys
        // Iterator over the public keys
        .iter()
        .enumerate()
        // Fold the new key plus all of the other keys
        .fold(G2Projective::from(G2Affine::zero()), |acc, (i, (_, proof))| {
            // I want `proofn = rng * n * ski`
            // What I have is `proofi = rng * i * ski`
             
            // First take the proof and multiply it by n!
            // Through bilinearity we can separate the proof into the sum of terms:
            // [rng * (i + 1) * s0] * [factorial / i + 1] * [n + 1]
            // = proof_i * [The rest of rho] * [n + 1]
            // We divide out factorial later
            let range = 0..(new_key_index);
            
            // This is n! divided by (i + 1)
            let factorial_except_i = range.fold(1, |acc, range_index| {
                // Range index is the 
                if range_index == i {
                    acc
                }
                else {
                    acc * (range_index + 1)
                }
            });

            acc - proof
            .mul(Fr::from(new_key_index as u64 + 1))
            .mul(Fr::from(factorial_except_i as u64))
        })
        .mul(inverse)
        // Transform into affine representation
        .into_affine();

    // The aggregated signature
    // If I just keep this zero, the bls verifies, LOL?
    let aggregate_signature = G2Affine::zero();

    /* End of solution */

    // Verify the new key + it's index + the new proof
    pok_verify(new_key, new_key_index, new_proof);
    // Aggregate all of the keys (Including new one), represent as affine
    let aggregate_key = public_keys
        // Iterator over the public keys
        .iter()
        // Fold the new key plus all of the other keys
        .fold(G1Projective::from(new_key), |acc, (pk, _)| acc + pk)
        // Transform into affine representation
        .into_affine();

    // Verify the signed message
    // (Using the aggregate of the keys, including the new one, the signature formed, and the message)
    bls_verify(aggregate_key, aggregate_signature, message)
}

const PUZZLE_DESCRIPTION: &str = r"
Bob has been designing a new optimized signature scheme for his L1 based on BLS signatures. Specifically, he wanted to be able to use the most efficient form of BLS signature aggregation, where you just add the signatures together rather than having to delinearize them. In order to do that, he designed a proof-of-possession scheme based on the B-KEA assumption he found in the the Sapling security analysis paper by Mary Maller [1]. Based the reasoning in the Power of Proofs-of-Possession paper [2], he concluded that his scheme would be secure. After he deployed the protocol, he found it was attacked and there was a malicious block entered the system, fooling all the light nodes...

[1] https://github.com/zcash/sapling-security-analysis/blob/master/MaryMallerUpdated.pdf
[2] https://rist.tech.cornell.edu/papers/pkreg.pdf
";
