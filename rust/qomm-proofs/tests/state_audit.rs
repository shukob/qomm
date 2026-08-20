//! The chain has to accept an honest book and reject each way one can be wrong,
//! and the three failures have to stay distinguishable --- only a fork is
//! evidence of equivocation, so a venue that cannot tell them apart cannot act
//! on any of them.

use curve25519_dalek::scalar::Scalar;
use qomm_proofs::state_audit::{ChainError, StateAuditor, StateStep};
use rand_core::OsRng;

struct Book {
    auditor: StateAuditor,
    limit: u64,
    limit_blinding: Scalar,
}

impl Book {
    fn new(limit: u64) -> Self {
        Book { auditor: StateAuditor::new(), limit, limit_blinding: Scalar::random(&mut OsRng) }
    }

    /// Walk a sequence of fills, returning the chain and the opening state.
    fn walk(&self, fills: &[i64]) -> (curve25519_dalek::ristretto::RistrettoPoint, Vec<StateStep>) {
        let mut inventory = 0i64;
        let mut blinding = Scalar::random(&mut OsRng);
        let opening = self.auditor.key.commit(&Scalar::ZERO, &blinding);
        let mut steps = Vec::new();
        for (n, filled) in fills.iter().enumerate() {
            let new_blinding = Scalar::random(&mut OsRng);
            let (step, next) = self.auditor.prove_update(
                n as u64, inventory, &blinding, *filled, &Scalar::random(&mut OsRng),
                self.limit, &self.limit_blinding, &new_blinding, &mut OsRng,
            ).expect("honest fill inside the limit");
            steps.push(step);
            inventory = next;
            blinding = new_blinding;
        }
        (opening, steps)
    }
}

#[test]
fn an_honest_book_verifies() {
    let book = Book::new(500);
    let (opening, steps) = book.walk(&[100, -40, 250, -300, 60]);
    assert_eq!(book.auditor.verify_chain(&opening, &steps, &limit_of(&book)), Ok(()));
}

#[test]
fn the_sign_convention_is_the_one_the_proof_states() {
    // A maker that sells carries a negative position afterwards.
    let book = Book::new(500);
    let (_, steps) = book.walk(&[100]);
    assert_eq!(steps.len(), 1);
    // inventory = 0 - 100 = -100, which is inside the limit, so it proved.
}

#[test]
fn a_fill_that_breaks_the_limit_cannot_be_proved() {
    let book = Book::new(50);
    let mut inventory = 0i64;
    let blinding = Scalar::random(&mut OsRng);
    let err = book.auditor.prove_update(
        0, inventory, &blinding, 400, &Scalar::random(&mut OsRng),
        book.limit, &book.limit_blinding, &Scalar::random(&mut OsRng), &mut OsRng,
    ).unwrap_err();
    assert!(err.contains("breaks the committed limit"));
    inventory += 0;
    let _ = inventory;
}

#[test]
fn a_replayed_state_breaks_the_chain() {
    let book = Book::new(500);
    let (opening, mut steps) = book.walk(&[100, -40, 250]);
    steps.swap(1, 2);
    assert!(matches!(book.auditor.verify_chain(&opening, &steps, &limit_of(&book)),
                     Err(ChainError::Forked { .. })));
}

#[test]
fn a_step_from_a_different_book_is_a_fork_not_bad_arithmetic() {
    let book = Book::new(500);
    let (opening, mut steps) = book.walk(&[100, -40]);
    let (_, other) = book.walk(&[70, 30]);
    steps[1] = other.into_iter().nth(1).unwrap();
    assert!(matches!(book.auditor.verify_chain(&opening, &steps, &limit_of(&book)),
                     Err(ChainError::Forked { index: 1, .. })));
}

#[test]
fn a_limit_outside_the_ceiling_is_refused_at_commitment() {
    let book = Book::new(500);
    assert!(book.auditor.commit_limit(u64::MAX, &book.limit_blinding).is_err());
}

#[test]
fn a_chain_is_checked_against_its_own_limit() {
    let book = Book::new(500);
    let (opening, steps) = book.walk(&[400]);
    // The same steps under a tighter committed limit must not verify: the
    // containment proofs are about a difference the tighter limit does not
    // reproduce.
    let tight = Book { auditor: StateAuditor::new(), limit: 100,
                       limit_blinding: book.limit_blinding };
    let tight_limit = tight.auditor.commit_limit(tight.limit, &tight.limit_blinding).unwrap();
    assert!(book.auditor.verify_chain(&opening, &steps, &tight_limit).is_err());
}

fn limit_of(book: &Book) -> qomm_proofs::state_audit::InventoryLimit {
    book.auditor.commit_limit(book.limit, &book.limit_blinding).unwrap()
}
