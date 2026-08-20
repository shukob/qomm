//! The proof has to accept the true winner and reject every way of claiming a
//! different one. Minimality is the property under test: membership alone would
//! let a prover open any key it liked.

use curve25519_dalek::scalar::Scalar;
use qomm_proofs::quote_proof::{Invalid, MakerWitness, QuoteCircuit};
use rand_core::OsRng;

fn makers() -> Vec<MakerWitness> {
    // half-spreads of 8, 5 and 12: the middle one should win an ask.
    [8i64, 5, 12].iter().enumerate().map(|(i, half)| MakerWitness {
        mid: 0, half: *half, slope: 1 + i as i64, invcoef: 1,
        inv: 10 * (i as i64 + 1), maxqty: 1_000, expiry: 10_000, active: true,
    }).collect()
}

const CTX: &[u8] = b"test";

#[test]
fn the_true_winner_verifies_and_is_the_tightest() {
    let circuit = QuoteCircuit::default();
    let (proof, public) = circuit
        .prove(&makers(), 100, 0, 1_000, 1 << 20, 4, CTX, &mut OsRng)
        .expect("honest makers prove");
    assert_eq!(circuit.verify(&proof, &public, CTX), Ok(()));
    // packed key = effective * n_slots + index, so the index rides in the low bits
    assert_eq!(proof.winner_value as usize % 4, proof.winner_index);
    // The tightest half-spread does not win by itself: cost carries the depth
    // term too, and maker 0's shallower slope beats maker 1's tighter quote at
    // this size. Asserting the winner rather than the half-spread is the point.
    assert_eq!(proof.winner_index, 0);
}

#[test]
fn claiming_a_loser_as_the_winner_fails_minimality() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(&makers(), 100, 0, 1_000, 1 << 20, 4, CTX, &mut OsRng)
        .expect("honest makers prove");
    proof.winner_index = 2;
    assert!(matches!(circuit.verify(&proof, &public, CTX),
                     Err(Invalid::WinnerDoesNotOpen) | Err(Invalid::NotMinimal)));
}

/// The gap this test exists for was real: an opening proof shows knowledge of
/// *some* opening, so binding the commitment alone leaves the published price a
/// free parameter and a venue can quote whatever it likes.
#[test]
fn a_tampered_winner_value_does_not_open() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(&makers(), 100, 0, 1_000, 1 << 20, 4, CTX, &mut OsRng)
        .expect("honest makers prove");
    proof.winner_value += 1;
    assert_eq!(circuit.verify(&proof, &public, CTX), Err(Invalid::WinnerDoesNotOpen));
}

#[test]
fn a_proof_does_not_carry_across_contexts() {
    let circuit = QuoteCircuit::default();
    let (proof, public) = circuit
        .prove(&makers(), 100, 0, 1_000, 1 << 20, 4, CTX, &mut OsRng)
        .expect("honest makers prove");
    assert!(circuit.verify(&proof, &public, b"another venue").is_err());
}

#[test]
fn the_direction_changes_who_wins() {
    let circuit = QuoteCircuit::default();
    // Selling pays the bid, and the slope now works the other way, so the
    // ordering is not the same one.
    let (ask, ask_public) = circuit
        .prove(&makers(), 100, 0, 1_000, 1 << 20, 4, CTX, &mut OsRng).unwrap();
    let (bid, bid_public) = circuit
        .prove(&makers(), 100, 1, 1_000, 1 << 20, 4, CTX, &mut OsRng).unwrap();
    assert_eq!(circuit.verify(&ask, &ask_public, CTX), Ok(()));
    assert_eq!(circuit.verify(&bid, &bid_public, CTX), Ok(()));
    assert_ne!(ask.winner_value, bid.winner_value);
}

#[test]
fn an_ineligible_maker_is_refused_rather_than_silently_priced() {
    let circuit = QuoteCircuit::default();
    let mut ms = makers();
    ms[0].maxqty = 10;                       // smaller than the request
    assert!(circuit.prove(&ms, 100, 0, 1_000, 1 << 20, 4, CTX, &mut OsRng).is_err());
}

#[test]
fn a_swapped_maker_commitment_breaks_its_own_product_proof() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(&makers(), 100, 0, 1_000, 1 << 20, 4, CTX, &mut OsRng).unwrap();
    let other = proof.maker_proofs[1].commitments.slope;
    proof.maker_proofs[0].commitments.slope = other;
    assert_eq!(circuit.verify(&proof, &public, CTX), Err(Invalid::Depth(0)));
}

#[test]
fn the_eligibility_aggregate_must_cover_the_stated_margins() {
    let circuit = QuoteCircuit::default();
    let (mut proof, public) = circuit
        .prove(&makers(), 100, 0, 1_000, 1 << 20, 4, CTX, &mut OsRng).unwrap();
    let key = &circuit.key;
    proof.maker_proofs[0].commitments.fits =
        key.commit(&Scalar::from(999u64), &Scalar::random(&mut OsRng));
    assert_eq!(circuit.verify(&proof, &public, CTX), Err(Invalid::Eligibility(0)));
}
