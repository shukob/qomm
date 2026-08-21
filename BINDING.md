# Binding what was computed to what was committed

The one gap in the middle of the stack, the two ways to close it, and what each
one costs. Every figure here is measured on `host-a` unless it says otherwise,
and every arm was verified against the cleartext answer before its time was
taken --- a timing from a run that computed the wrong thing is not a timing.

`DEPLOYMENT.md` points here from section 0; this used to be section 0.6 of it,
and grew until it was half of a document about where to put nodes.

---

## 0. What is open

A maker deals its policy to the seven computing nodes as shares. A node can
check its own share against the dealer's commitment before it computes
(`check_share`). **What nothing forces is that the value the node then puts into
MP-SPDZ is the share it checked.**

`qomm_transport/roles.py` says so in the code rather than leaving it to be
discovered: the signature on a dealt share buys **detection and attribution, not
prevention**. A node that substitutes an input can be shown afterwards to have
done it.

**Whether that is enough is a question about who the nodes are.** Seven KYB'd
legal entities with a bond to slash and a jurisdiction to be sued in are held by
attribution; prevention buys them little. Seven anonymous operators are not held
by anything, and everything below is for that case.

The same gap sits under three modules, and it is one gap rather than three.
`policy_audit.py` states it exactly:

> these shares are not the shares MP-SPDZ consumes. MP-SPDZ works over its own
> prime field, so an end-to-end binding needs the computation to run over the
> same field as the commitments, **or a commit-and-prove link between the two**.

Those are the two ways. They are sections 2 and 3.

---

## 1. Why the field is what stands in the way

`threshold_sigma` is how the nodes prove anything about a value none of them
holds. A sigma response is

    z = k + c * w

which is **affine in the witness**, so each node computes `z_i = k_i + c * w_i`
from its own share and the pieces Lagrange-combine into `z` --- in the **scalar
field of the group**. That is the whole method, and it is why this design uses
sigma protocols instead of a general-purpose SNARK.

It works only if the shares are over the group order. MP-SPDZ works over its own
prime, so today the proof is assembled from shares nobody can show are the
computation's.

**Two proofs need this and two do not.** `policy_audit.py` and `state_audit.py`
never import `threshold_sigma`: a maker proving something about its own policy
knows the witness and proves alone. The quote proof and zkPI are assembled from
node shares, and they are where the field matters --- and they are also the
system's headline claim, that the returned price was the minimum and anyone can
check it.

---

## 2. Matching the field

Run MP-SPDZ over the ed25519 group order and the Lagrange combination becomes
valid as written. No new cryptography; the existing code starts meaning what it
says.

Both arms in one session on one machine, every arm verified (M=16, 31 bits,
4 assets, N=7):

| | rounds | global traffic | wall @15 ms | wall @120 ms |
|---|---:|---:|---:|---:|
| MP-SPDZ default field | 64 | 19.37 MB | 3.621 s | 27.603 s |
| ed25519 scalar field, 253 bits | **64** | **38.73 MB** | **3.877 s** | **29.179 s** |
| ratio | **1.00x** | **2.00x** | **1.07x** | **1.06x** |

**Rounds do not move. Traffic is exactly 2.00x, which is the element width going
from 16 bytes to 32 and nothing else. Wall clock is 7% at 15 ms and 6% at
120 ms** --- cheaper cross-region, because the round count is unchanged and the
round trip is what dominates there.

**So matching the field is affordable, and that decides most of this document.**
`threshold_sigma` assembles, the quote proof is publicly verifiable, and it costs
six to eight per cent.

### 2.1 The seven-times error that this section used to report

The first version of this measurement reported **2.02x rounds and 14.3x
traffic**, and everything downstream was reasoned from it: which field to take,
whether the input check was worth building, what the throughput was
cross-region, whether a different group or a smaller field would help.

**All of it was one wrong flag.** The circuit was compiled with `-P <prime>`.
MP-SPDZ prints, in the compile output of every such run:

> `WARNING: --prime/-P activates code that usually isn't the most efficient
> variant. Consider using --field/-F and set the prime only during the actual
> computation.`

That warning was in the output every time and was not read. Compiling with
`-F <bits>` and giving the prime to the virtual machine at run time is the
supported path, and it removes the entire penalty.

**Three things were then measured against a problem that did not exist**, and
they are worth keeping for what they say about the tool rather than about the
question:

- **edaBits** made it two orders of magnitude worse --- 2,920 MB on the default
  field, 6,257 MB on the matched one. They are preprocessing, and this harness
  measures one phase, so their generation lands in the run with nowhere to hide.
  A real offline stage is still unmeasured.
- **Probabilistic truncation** changed nothing at all, to the decimal.
- **`audit_gates` and `public_maker_assets` together** took 277.3 MB to 137.3 MB.
  Real levers, and they still work --- they are just no longer needed for this.

And the literature was searched for a way around a barrier that was not there.
**Rabbit** (Makri, Rotaru, Vercauteren, Wagh, FC 2021) removes the statistical
security requirement that makes comparison cost scale with the field, "allowing
MPC protocols to be run in a field of arbitrary size" --- and MP-SPDZ already
implements it, gated on the prime being close to a power of two, which the
ed25519 order is by a margin of `2^-127`. The fast path was available the whole
time; the compile flag was not letting it be reached.

**The lesson is not about MP-SPDZ.** A seven-times figure was published to three
repositories and a slide deck, and used as the premise of four subsequent
decisions, while the tool printed the reason in plain English on every run.

## 3. Checking the inputs instead

`zk/input_check.py`. The dealer already publishes a commitment per input. Once
the inputs are fixed, public coefficients are derived from those commitments by
Fiat--Shamir, the circuit computes

    s = sum_j c_j v_j + r

for a committed mask `r`, and opens `s`. Pedersen commitments add, so the same
coefficients combine the commitments into one that `s` must open. A node that
feeds the circuit `v_j + e_j` shifts `s` by `sum_j c_j e_j`, and the coefficients
it would have to satisfy did not exist when it chose `e`.

**Public coefficient times secret share is local**, so the combination costs no
communication; the opening is the round.

### 3.1 The width budget, which decides where it can run

The whole argument is that **the same integer appears on both sides**, so the
opening must not reduce in either field. Two things have to fit, and the second
is the one that bites: `r` is an input like any other, dealt through
`roles.split` additively over the integers with `SLACK_BITS` of room per share.
**The forty bits are spent twice** --- once hiding the combination in the
opening, once hiding each share from its node.

    field needed = value_bits + challenge_bits + log2(n) + hiding_gap
                              + share_slack + log2(nodes) + 2

At 32-bit values and 166 inputs that is `challenge_bits + hiding_gap <= 41` in a
127-bit prime. Forty-bit coefficients need **165 bits** and do not fit.
**Six-bit coefficients need 126 and do.**

Narrow coefficients lose soundness, and **repetition buys it back for free in
rounds** --- independent combinations wait on nothing and open together. Seven
six-bit rounds are `2^-42`, clearing the `2^-40` the rest of the stack works to.

### 3.2 What repetition cannot buy back

The hiding. More repetitions dilute the gap while buying soundness, so the curve
has a peak --- **about `2^-34`, at two to four coefficient bits with eleven to
twenty-six repetitions** --- and `2^-40` is out of reach at 127 bits anywhere on
it. The shipped six-by-seven setting sits at `2^-32`. `narrow_tradeoff` tabulates
the curve and a test holds the peak.

**This is the honest cost of running the check in the narrow field**, and it is
the only one.

### 3.3 Measured

Cryptography, over 166 inputs, ed25519, `host-a`: **16.4 ms to build, 13.9 ms to
verify**, which is 204 scalar multiplications. 34 tests: a substituted input
caught at every position and error size, two errors that try to cancel caught,
coefficients that move when the commitments move, an opening that differs every
time.

In the circuit, both arms verified:

| | rounds | global | wall @15 ms |
|---|---:|---:|---:|
| default field, no check | 64 | 19.37 MB | 3.583 s |
| **default field, input check (6 bits x 7)** | **65** | **19.38 MB** | **3.631 s** |
| 177 bits, input check | 125 | 150.84 MB | 6.377 s |
| group order, no check | 129 | 277.26 MB | 7.783 s |

**One round, six kilobytes, forty-seven milliseconds.**

---

## 4. Which one to take

| | binds the inputs | quote proof publicly verifiable | cost |
|---|---|---|---|
| default field | no | no | --- |
| default field + check | yes | no | +1 round, +6 KB |
| **group order (253 bits)** | **yes** | **yes** | **2.00x traffic, 1.07x wall** |
| group order + check | yes | yes | the above, +1 round |

**Take the group order.** It is six to eight per cent of the wall clock and
twice the bytes --- 5.5 MB a node a quote against 2.8 --- and it buys the
publicly verifiable quote proof, which is the system's headline claim.

**The input check is no longer the cheap alternative to that.** It is still
worth having and still costs one round on the matched field (measured: 65 rounds
against 64, +0.013 MB), but as a **fast pre-check**: it catches a substituted
input at once rather than when a 317 ms proof fails to verify. Defence in depth
rather than a substitute.

The narrow-field version of the check in section 3 remains the answer for a
deployment that skips the quote proof entirely --- profile A in
`DEPLOYMENT.md`, where latency is everything and correctness proofs are not
produced.

## 5. Would a different group be cheaper? No

**The field size is what costs, and 128-bit security forces about 256 bits of
scalar field for any discrete-log group**, elliptic curve or multiplicative. No
discrete-log scheme shrinks the MPC field.

What the group does change is the speed of the proofs, and `zk_bench.json`
already had it --- one host, one proof, seven fields, seven parties:

| backend | prove | verify | share check |
|---|---:|---:|---:|
| ed25519 | 14.4 ms | 15.5 ms | 7.6 ms |
| modp multiexp | 4,865.6 ms | 7,358.6 ms | 1,419.0 ms |
| ratio | **338x** | **475x** | **187x** |

A non-curve group is worse on one axis and neutral on the other.

**The one direction that could shrink the field is lattice commitments**, whose
security comes from dimension rather than modulus size. Section 6 is why that
does not simply work.

---

## 6. Post-quantum

**Scope first, because the two halves are not the same difficulty.**

| | who proves | which | cost |
|---|---|---|---|
| **single prover** | the maker, knowing its own secret | policy audit, state audit, range proofs, the input check | **size only** |
| **threshold-assembled** | seven nodes, about a value none holds | **quote proof**, zkPI | **structural** |

**The confidential computation is already post-quantum.** Shamir with an honest
majority is information-theoretically secure; there is no assumption to break
and the MPC layer needs nothing.

**And the next part is nearly as favourable.** Pedersen is *perfectly* hiding and
only computationally binding, so a quantum adversary can open a commitment to a
value it does not hold and can **never learn the value**. What quantum takes away
is the ability to prove, never the ability to hide.

### 6.1 Three obstacles, in increasing difficulty

**Size.** A sigma proof here is `4,960` bytes a step, measured
(`state_audit.json`). Lattice equivalents are kilobytes to tens of kilobytes ---
from the literature, not measured here. Bandwidth, and the design does not
change.

**Rejection sampling.** A lattice response `z = y + c*s` leaks `s` unless the
prover sometimes discards it and restarts, and **the abort test is on the
combined `z` rather than on any share**. The nodes would have to reconstruct `z`
to decide, and a rejection then arrives *after* the leak it exists to prevent.
Each retry needs fresh randomness across all nodes, at two to seven expected
attempts. A one-shot assembly becomes an interactive protocol.

**Shortness against Shamir**, which is the structural one. Lattice soundness
needs a **short** witness. Shamir shares are uniform in `Z_q`, Lagrange
coefficients are arbitrary elements of it, and the combination is literally

```python
z_value = sum(coefficients[p] * partials[p][0] for p in partials) % order
```

--- short things multiplied by large things and reduced. **Shortness does not
survive.** Not a tunable parameter: a mismatch between how Shamir reconstructs
and what lattice soundness requires.

### 6.2 Ways out, and their price

**Replicated secret sharing** keeps shortness, because reconstruction is a plain
sum with `{0,1}` coefficients. At seven nodes and `T=2` that is `C(7,2) = 21`
shares with `C(6,2) = 15` held by each party --- fifteen times the per-party
storage and the multiplication cost that follows --- and it does not scale past
small `n`. **Small-coefficient sharing schemes** exist and trade against
threshold flexibility. **Threshold lattice signatures** are active research whose
known constructions are heavier and need more rounds.

### 6.3 What the signatures cost, which is size and not speed

ML-DSA signs about as fast as Ed25519 in optimised implementations. The bytes
land on the maker update path. Sizes are the standard's, checked against an
implementation; **no timing is claimed**, because the only implementation
available here is pure Python.

| signature | one full policy update | vs now | 10 updates/s, 16 makers |
|---|---:|---:|---:|
| Ed25519 | 10,836 B | 1.0x | 0.19 MB/s |
| ML-DSA-44 | 159,264 B | **14.7x** | 2.83 MB/s |
| ML-DSA-65 | 215,271 B | 19.9x | 3.83 MB/s |
| SLH-DSA-128s | 501,732 B | 46.3x | 8.92 MB/s |

**Fifteen times the bytes, and under three megabytes a second at rates a real
market maker uses.**

**So most of the stack goes post-quantum for a size penalty, and the quote proof
needs a construction this repository does not have** --- which is the same
construction section 5 wanted. Whichever reason takes you to lattices, the work
is the same work: **an assembly method that does not need the response to be
linear in the witness.**

---

## 7. What a quantum network would change, which is one thing

**It closes the one place this system is still computational.** The MPC is
unconditional; the traffic between the nodes runs over TLS. An eavesdropper who
records every link today and breaks TLS later holds every share and
reconstructs. **The computation is unconditional and the pipe carrying it is
not.**

The deployment shape is the one QKD can serve: seven fixed, long-lived, known
endpoints --- and `DEPLOYMENT.md` section 0 already puts them in one metropolitan
area for latency, which is the range at which QKD works.

**It cannot one-time-pad the traffic.** Against measured volumes:

| | traffic a quote | key rate for a one-time pad |
|---|---:|---:|
| default field, 0.4 quotes/s | 19.4 MB | **62 Mbps** |
| default field, 3 quotes/s | 19.4 MB | 465 Mbps |
| matched field, 0.4 quotes/s | 277.3 MB | 887 Mbps |

Metro-scale QKD produces roughly 0.1 to 10 Mbps --- literature, not measured
here --- so even the cheapest row is one to two orders short. A deployment would
rekey a symmetric cipher instead, **and symmetric ciphers are already
quantum-safe**: Grover halves the effective key strength and AES-256 absorbs it.
**The real gain is narrower than it sounds: not having to trust the key-exchange
assumption.** Against store-now-decrypt-later that is still a genuine defence.

**Where it cannot help, and not for engineering reasons.** Unconditionally secure
bit commitment is **impossible even with quantum mechanics** (Mayers; Lo--Chau,
1997). Quantum does not rescue the commitments, so section 6 is not avoidable by
building a quantum network instead.

The reason generalises: **a proof has to convince someone who was not on the
link** --- an auditor, a supervisor, a counterparty checking years later. QKD
secures a channel between two parties who are both present. Quantum digital
signatures exist but need quantum memory or repeated distribution and their
transferability is limited, so they do not give "anyone can verify this
afterwards" either.

| | does a quantum network change it |
|---|---|
| the MPC layer's security | no --- already unconditional |
| **confidentiality of inter-node traffic** | **yes --- this is the one** |
| commitments | no, by a no-go theorem rather than by engineering |
| the quote proof | no --- it must convince someone who was not there |
| signatures | no --- they must be transferable and checkable later |

*Quantum secret sharing* would distribute shares over quantum channels with
eavesdropping detection, but the shares here are classical, so the benefit
collapses into the row above. *Anonymous transmission* through entanglement
would hide which participant sent a request --- the transport layer's job,
approximated today by batching and shuffling on a fixed schedule --- and is
theoretically stronger and practically remote.

**A quantum network makes the pipe unconditional, not the proof.**

---

## 8. What the matched field leaves cross-region

**Almost exactly what the default field leaves**, because the round count does
not move and a wide-area quote is round-trip bound. Measured at 120 ms one way,
verified:

| | rounds | global | wall | vs default |
|---|---:|---:|---:|---:|
| default field, one request | 64 | 19.37 MB | 27.603 s | --- |
| **group order, one request** | **64** | **38.73 MB** | **29.179 s** | **1.06x** |
| default field, batch of 32 | 259 | 637.1 MB | 105.96 s | --- |

**Six per cent.** The earlier version of this section reported the matched field
at 0.036 quotes a second against 0.75 for the default --- a twenty-fold gap that
was the compile flag, not the field.

What survives from that work is the shape of batching, which is a property of
the circuit rather than of the field: **rounds grow with the batch** --- 64 to
259 from one request to thirty-two --- so batching trades the quote's age for
throughput. A batch of 32 is 3.3 s a quote against 27.6 s, eight times better,
for an age of 106 s against 28 s. Against `staleness.json`, where 96 seconds is
1.34 to 1.75 times the within-block floor, that is a good trade, and **batches of
8 to 32 are where throughput and age meet.**

## 9. Every prediction in this document that missed

Kept together rather than scattered, because a document that shows only the
predictions that landed is advertising a discipline rather than reporting one.

| predicted | measured | direction |
|---|---|---|
| matched field leaves the round count unchanged | **1.00x** | **landed** --- and was then reported as 2.02x for a week because of the compile flag |
| matched field costs about 2x traffic, from 16-byte elements becoming 32 | **2.00x** | **landed exactly**, and was likewise reported as 14.3x |
| edaBits reduce it | 150x worse --- preprocessing measured in a single-phase harness | wrong phase, **and against a problem that did not exist** |
| probabilistic truncation gives 150 to 250 MB | no change at all | wrong, same |
| the input check is free: one round and one field element | true of the opening; the mask was not counted | incomplete |
| the check therefore cannot run at 127 bits | it runs --- the first split of the budget that failed was taken for the whole budget | wrong |
| 2^-40 hiding is unreachable at 127 bits; then reachable; then unreachable | unreachable, ceiling about 2^-34 | resolved by measuring |
| 177-bit field: 4--9x traffic, 96--129 rounds, 1.4--1.9x wall | 7.8x, 124, 1.71x | landed, **against the wrong baseline** |
| the check adds 1 to 3 rounds | **1** | landed |
| cross-region at a batch of 32: 347 rounds, 0.38 quotes/s | 1,314 rounds, 0.036 --- extrapolating a ratio that was itself growing | 10x too generous, **and the ratio was an artifact** |
| compiling with `-F` instead of `-P` gives 2--6x traffic and 1.0--1.4x rounds | **2.00x and 1.00x** | landed |

**The two most important predictions in this document were right the first
time**, and were then buried under a measurement that contradicted them for a
week. When arithmetic said the cost should be the element width and the
measurement said fourteen times, the arithmetic was correct and the harness was
misconfigured --- and the tool was printing the reason on every run.

That is the finding to carry out of here. The other errors were counting
mistakes, which are cheap to find once someone counts again. **This one was a
disagreement between theory and measurement that got resolved in favour of the
measurement without asking why they disagreed**, and it cost four sections and a
published slide.
