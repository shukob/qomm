//! Publicly verifiable proof that the opened quote is the correct one.
//!
//! Receipts bind a node to a result; they do not show the result is right. This
//! closes that gap for the quote circuit, without a general-purpose SNARK and
//! without a trusted setup, by proving the statement the circuit computes:
//!
//! > for each maker `i`, `key_i` is the committed policy applied to the
//! > committed request, and the opened winner is the smallest of those keys.
//!
//! Every step is a sigma protocol over Pedersen commitments, which matters
//! twice. Sigma responses are affine in the witness, so a quorum of computing
//! nodes can assemble the proof from shares without any of them holding it. And
//! the result is checked by an ordinary verifier with no setup.
//!
//! Per maker:
//!
//! ```text
//! depth_i = slope_i * qty              product proof
//! skew_i  = invcoef_i * inv_i          product proof
//! ask_i   = mid_i + half_i + depth_i + skew_i     linear, free
//! bid_i   = mid_i - half_i - depth_i + skew_i     linear, free
//! fits_i  = maxqty_i - qty >= 0        range proof
//! fresh_i = expiry_i - now  >= 0       range proof
//! ok_i    is a bit, and gates the cost bit + product proofs
//! key_i   = cost_i * M + i             linear, free
//! ```
//!
//! and over the whole set: the winner's commitment opens to the revealed value,
//! and `key_i - v >= 0` for every `i`. Minimality plus membership is exactly
//! "v is the minimum", so an incorrect winner cannot be proved.
//!
//! One difference from the Python this replaces. Range proofs there were bit
//! decompositions at an arbitrary width; here they are Bulletproofs, which take
//! powers of two, so a declared width rounds up. Each maker's two eligibility
//! ranges share one aggregated proof, and so do the minimality ranges, which is
//! why the proof does not grow linearly the way the original did.

use bulletproofs::RangeProof;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use qomm_zk::pedersen::Pedersen;
use qomm_zk::range::RangeCtx;
use qomm_zk::sigma::{
    prove_bit, prove_opening, prove_product, verify_bit, verify_opening, verify_product,
    BitProof, OpeningProof, ProductProof,
};
use rand_core::{CryptoRng, RngCore};

/// A maker's secret policy and state. Never leaves the maker or the quorum.
#[derive(Clone, Copy, Debug)]
pub struct MakerWitness {
    pub mid: i64,
    pub half: i64,
    pub slope: i64,
    pub invcoef: i64,
    pub inv: i64,
    pub maxqty: i64,
    pub expiry: i64,
    pub active: bool,
}

/// The commitments a verifier needs to reconstruct one maker's statement.
#[derive(Clone, Debug)]
pub struct MakerCommitments {
    pub slope: RistrettoPoint,
    pub invcoef: RistrettoPoint,
    pub inv: RistrettoPoint,
    pub depth: RistrettoPoint,
    pub skew: RistrettoPoint,
    pub fits: RistrettoPoint,
    pub fresh: RistrettoPoint,
    pub active: RistrettoPoint,
    pub ok: RistrettoPoint,
    pub cost: RistrettoPoint,
    pub gated: RistrettoPoint,
    pub shifted_cost: RistrettoPoint,
}

#[derive(Debug)]
pub struct MakerProof {
    pub depth: ProductProof,
    pub skew: ProductProof,
    pub gate_cost: ProductProof,
    /// One aggregated proof covering both `fits` and `fresh`.
    pub eligibility: RangeProof,
    pub eligibility_commitments: Vec<CompressedRistretto>,
    pub active_bit: BitProof,
    pub ok_bit: BitProof,
    pub commitments: MakerCommitments,
}

#[derive(Debug)]
pub struct QuoteProof {
    pub winner_index: usize,
    pub winner_value: u64,
    pub maker_proofs: Vec<MakerProof>,
    pub winner_opening: OpeningProof,
    /// One aggregated proof that every key is at least the winner's.
    pub minimality: RangeProof,
    pub minimality_commitments: Vec<CompressedRistretto>,
    pub key_commitments: Vec<RistrettoPoint>,
}

/// What the verifier is told in the clear.
#[derive(Clone, Copy, Debug)]
pub struct Public {
    pub qty_commitment: RistrettoPoint,
    pub now: i64,
    pub sentinel: i64,
    pub n_slots: i64,
    /// 0 = the user buys and pays the ask, 1 = the user sells and receives the bid.
    pub direction: u8,
}

pub struct QuoteCircuit {
    pub key: Pedersen,
    eligibility_bits: usize,
    span_bits: usize,
}

fn scalar(value: i64) -> Scalar {
    if value < 0 { -Scalar::from(value.unsigned_abs()) } else { Scalar::from(value as u64) }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    Depth(usize),
    Skew(usize),
    Eligibility(usize),
    ActiveNotABit(usize),
    OkNotABit(usize),
    CostNotGated(usize),
    WinnerDoesNotOpen,
    NotMinimal,
}

impl Default for QuoteCircuit {
    fn default() -> Self { Self::new(32, 32) }
}

impl QuoteCircuit {
    /// `eligibility_bits` bounds the size and expiry margins; `span_bits` bounds
    /// how far a key can sit above the winner. Both round up to a power of two.
    pub fn new(eligibility_bits: usize, span_bits: usize) -> Self {
        QuoteCircuit {
            key: Pedersen::new(b"qomm:policy:v1"),
            eligibility_bits,
            span_bits,
        }
    }

    fn ranges(&self, bits: usize, count: usize) -> RangeCtx {
        RangeCtx::new(bits, count.next_power_of_two().max(1))
    }

    fn tag(context: &[u8], index: usize, part: &str) -> Transcript {
        let mut t = Transcript::new(b"qomm:quote:v1");
        t.append_message(b"ctx", context);
        t.append_u64(b"mm", index as u64);
        t.append_message(b"part", part.as_bytes());
        t
    }

    fn whole(context: &[u8], part: &str) -> Transcript {
        let mut t = Transcript::new(b"qomm:quote:v1");
        t.append_message(b"ctx", context);
        t.append_message(b"part", part.as_bytes());
        t
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: RngCore + CryptoRng>(
        &self, makers: &[MakerWitness], qty: i64, direction: u8, now: i64,
        sentinel: i64, n_slots: i64, context: &[u8], rng: &mut R,
    ) -> Result<(QuoteProof, Public), &'static str> {
        let key = &self.key;
        let r_qty = Scalar::random(rng);
        let c_qty = key.commit(&scalar(qty), &r_qty);

        let mut keys: Vec<u64> = Vec::with_capacity(makers.len());
        let mut key_blindings: Vec<Scalar> = Vec::with_capacity(makers.len());
        let mut key_commitments: Vec<RistrettoPoint> = Vec::with_capacity(makers.len());
        let mut maker_proofs: Vec<MakerProof> = Vec::with_capacity(makers.len());

        for (index, m) in makers.iter().enumerate() {
            let (r_slope, r_invcoef, r_inv) =
                (Scalar::random(rng), Scalar::random(rng), Scalar::random(rng));
            let c_slope = key.commit(&scalar(m.slope), &r_slope);
            let c_invcoef = key.commit(&scalar(m.invcoef), &r_invcoef);
            let c_inv = key.commit(&scalar(m.inv), &r_inv);

            let r_depth = Scalar::random(rng);
            let depth = m.slope * qty;
            let depth_proof = prove_product(
                key, &mut Self::tag(context, index, "depth"), &c_slope,
                &scalar(m.slope), &r_slope, &scalar(qty), &r_qty, &r_depth, rng);

            let r_skew = Scalar::random(rng);
            let skew = m.invcoef * m.inv;
            let skew_proof = prove_product(
                key, &mut Self::tag(context, index, "skew"), &c_invcoef,
                &scalar(m.invcoef), &r_invcoef, &scalar(m.inv), &r_inv, &r_skew, rng);

            let (r_mid, r_half) = (Scalar::random(rng), Scalar::random(rng));
            let ask = m.mid + m.half + depth + skew;
            let bid = m.mid - m.half - depth + skew;
            let r_ask = r_mid + r_half + r_depth + r_skew;
            let r_bid = r_mid - r_half - r_depth + r_skew;

            // Eligibility: both margins in one aggregated range proof.
            let (r_maxqty, r_expiry) = (Scalar::random(rng), Scalar::random(rng));
            let fits = m.maxqty - qty;
            let fresh = m.expiry - now;
            if fits < 0 || fresh < 0 {
                // An ineligible maker still takes part, but through the gate
                // rather than through a range proof it cannot produce.
                return Err("this prover requires eligible makers; \
                            gate ineligible ones out before proving");
            }
            let r_fits = r_maxqty - r_qty;
            let ranges = self.ranges(self.eligibility_bits, 2);
            let mut t = Self::tag(context, index, "eligibility");
            let (eligibility, eligibility_commitments) =
                ranges.prove(&mut t, &[fits as u64, fresh as u64], &[r_fits, r_expiry])?;
            let c_fits = key.commit(&scalar(fits), &r_fits);
            let c_fresh = key.commit(&scalar(fresh), &r_expiry);

            let r_active = Scalar::random(rng);
            let c_active = key.commit(&Scalar::from(u64::from(m.active)), &r_active);
            let active_bit = prove_bit(key, &mut Self::tag(context, index, "active"),
                                       &c_active, m.active, &r_active, rng);

            let ok = m.active && qty <= m.maxqty && m.expiry > now;
            let r_ok = Scalar::random(rng);
            let c_ok = key.commit(&Scalar::from(u64::from(ok)), &r_ok);
            let ok_bit = prove_bit(key, &mut Self::tag(context, index, "ok"),
                                   &c_ok, ok, &r_ok, rng);

            let cost = if direction == 1 { -bid } else { ask };
            let r_cost = if direction == 1 { -r_bid } else { r_ask };
            let c_cost = key.commit(&scalar(cost), &r_cost);

            // gated = ok * (cost - sentinel), so gated + sentinel is the
            // effective cost: an ineligible maker lands exactly on the sentinel
            // without the circuit branching on why.
            let r_gated = Scalar::random(rng);
            let shifted_cost = cost - sentinel;
            let c_shifted = key.commit(&scalar(shifted_cost), &r_cost);
            let gate_cost = prove_product(
                key, &mut Self::tag(context, index, "gate"), &c_ok,
                &Scalar::from(u64::from(ok)), &r_ok, &scalar(shifted_cost), &r_cost,
                &r_gated, rng);
            let gated_value = if ok { shifted_cost } else { 0 };
            let c_gated = key.commit(&scalar(gated_value), &r_gated);

            let effective = gated_value + sentinel;
            let packed = effective * n_slots + index as i64;
            if packed < 0 {
                return Err("a packed key went negative; widen the sentinel");
            }
            let r_packed = r_gated * scalar(n_slots);
            keys.push(packed as u64);
            key_blindings.push(r_packed);
            key_commitments.push(key.commit(&Scalar::from(packed as u64), &r_packed));

            maker_proofs.push(MakerProof {
                depth: depth_proof, skew: skew_proof, gate_cost,
                eligibility, eligibility_commitments,
                active_bit, ok_bit,
                commitments: MakerCommitments {
                    slope: c_slope, invcoef: c_invcoef, inv: c_inv,
                    depth: key.commit(&scalar(depth), &r_depth),
                    skew: key.commit(&scalar(skew), &r_skew),
                    fits: c_fits, fresh: c_fresh, active: c_active, ok: c_ok,
                    cost: c_cost, gated: c_gated, shifted_cost: c_shifted,
                },
            });
        }

        let winner = (0..keys.len()).min_by_key(|i| keys[*i]).ok_or("no makers")?;
        let value = keys[winner];
        // Bind the *published* number, not merely the commitment. An opening
        // proof shows knowledge of some opening and says nothing about which, so
        // proving the winner's commitment directly would leave the price a free
        // parameter: a venue could publish any figure and the proof would still
        // verify. Proving that C_winner - g^value is a pure power of h says the
        // commitment opens to this value and no other, at the same cost.
        let residual = key.shift(&key_commitments[winner], value);
        let winner_opening = prove_opening(
            key, &mut Self::whole(context, "winner"), &residual,
            &Scalar::ZERO, &key_blindings[winner], rng);

        // Minimality: every key is at least the winner's, in one aggregated proof.
        let differences: Vec<u64> = keys.iter().map(|k| k - value).collect();
        let diff_blindings: Vec<Scalar> =
            key_blindings.iter().map(|r| r - key_blindings[winner]).collect();
        let ranges = self.ranges(self.span_bits, differences.len());
        let mut t = Self::whole(context, "minimality");
        let (minimality, minimality_commitments) =
            ranges.prove(&mut t, &differences, &diff_blindings)?;

        Ok((QuoteProof {
            winner_index: winner, winner_value: value, maker_proofs, winner_opening,
            minimality, minimality_commitments, key_commitments,
        }, Public {
            qty_commitment: c_qty, now, sentinel, n_slots, direction,
        }))
    }

    pub fn verify(
        &self, proof: &QuoteProof, public: &Public, context: &[u8],
    ) -> Result<(), Invalid> {
        let key = &self.key;
        for (index, maker) in proof.maker_proofs.iter().enumerate() {
            let c = &maker.commitments;
            if !verify_product(key, &mut Self::tag(context, index, "depth"),
                               &c.slope, &public.qty_commitment, &c.depth, &maker.depth) {
                return Err(Invalid::Depth(index));
            }
            if !verify_product(key, &mut Self::tag(context, index, "skew"),
                               &c.invcoef, &c.inv, &c.skew, &maker.skew) {
                return Err(Invalid::Skew(index));
            }
            // The aggregate must cover the two margins the statement is about,
            // and not two other numbers.
            let expected = [c.fits.compress(), c.fresh.compress()];
            if maker.eligibility_commitments.len() < 2
                || maker.eligibility_commitments[..2] != expected {
                return Err(Invalid::Eligibility(index));
            }
            let ranges = self.ranges(self.eligibility_bits, 2);
            let mut t = Self::tag(context, index, "eligibility");
            if !ranges.verify(&mut t, &maker.eligibility, &maker.eligibility_commitments) {
                return Err(Invalid::Eligibility(index));
            }
            if !verify_bit(key, &mut Self::tag(context, index, "active"),
                           &c.active, &maker.active_bit) {
                return Err(Invalid::ActiveNotABit(index));
            }
            if !verify_bit(key, &mut Self::tag(context, index, "ok"), &c.ok, &maker.ok_bit) {
                return Err(Invalid::OkNotABit(index));
            }
            if !verify_product(key, &mut Self::tag(context, index, "gate"),
                               &c.ok, &c.shifted_cost, &c.gated, &maker.gate_cost) {
                return Err(Invalid::CostNotGated(index));
            }
        }

        // Reconstructed from the published value, so a proof made for one price
        // does not carry to another.
        let residual = key.shift(&proof.key_commitments[proof.winner_index],
                                 proof.winner_value);
        if !verify_opening(key, &mut Self::whole(context, "winner"),
                           &residual, &proof.winner_opening) {
            return Err(Invalid::WinnerDoesNotOpen);
        }

        let winner = proof.key_commitments[proof.winner_index];
        let expected: Vec<CompressedRistretto> = proof.key_commitments.iter()
            .map(|c| (c - winner).compress()).collect();
        if proof.minimality_commitments.len() < expected.len()
            || proof.minimality_commitments[..expected.len()] != expected[..] {
            return Err(Invalid::NotMinimal);
        }
        let ranges = self.ranges(self.span_bits, expected.len());
        let mut t = Self::whole(context, "minimality");
        if !ranges.verify(&mut t, &proof.minimality, &proof.minimality_commitments) {
            return Err(Invalid::NotMinimal);
        }
        Ok(())
    }
}
