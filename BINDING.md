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

Both arms in one session on one machine, both verified (M=16, 31 bits, 4 assets,
N=7):

| | rounds | global traffic | wall @15 ms | wall @0 ms |
|---|---:|---:|---:|---:|
| MP-SPDZ `-F 128` | 64 | 19.4 MB | 3.626 s | 0.167 s |
| ed25519 scalar field, 253 bits | **129** | **277.3 MB** | **7.486 s** | **0.419 s** |
| ratio | **2.02x** | **14.3x** | **2.06x** | **2.50x** |

**The price is round count and arithmetic width, not transfer.** Fourteen times
the bytes buys only two to two and a half times the clock, and the ratio is
*worse* at zero delay than at 15 ms --- the opposite of a bandwidth-bound cost.

Two caveats before treating 2x as the number. The seven parties share one
machine and the delay proxy models latency but **not bandwidth**, so 277 MB a
quote --- about 40 MB a node, a third of a second on a gigabit link and three
seconds on a hundred-megabit one --- is a cost the measurement does not show.
And the 2x is paid on **every gate of every quote**.

### 2.1 What brings 277 MB down, and what does not

**edaBits: two orders of magnitude worse.** The obvious first try, since
comparison cost is meant to scale with the value width rather than the field
width --- exactly the 31-against-253 mismatch the traffic is made of. Measured:
**2,920 MB** on the default field and **6,257 MB** on the matched one, at 1,582
and 2,042 rounds. Not because the technique is bad: edaBits are preprocessing
and this harness measures one phase, so their generation lands in the run with
nowhere to hide. **This measures the wrong phase for them**, and the right
measurement needs an offline stage the bundled tool does not produce.

**Probabilistic truncation: no effect at all.** `program.use_trunc_pr` left
rounds and bytes identical to the decimal, so the comparison path it targets is
not the one this circuit takes.

**Two levers already in the circuit halve it.** `audit_gates` stops paying twice
for the expiry and active facts the registration audit already proves;
`public_maker_assets` turns the asset gate into a public index into a secret
one-hot vector, at no communication.

| matched field, plus | rounds | global | wall @15 ms | vs default field |
|---|---:|---:|---:|---:|
| nothing | 129 | 277.3 MB | 7.39 s | 14.3x / 2.04x |
| `audit_gates` | 122 | 216.9 MB | 6.59 s | 11.2x / 1.82x |
| `public_maker_assets` | 123 | 197.7 MB | 6.53 s | 10.2x / 1.80x |
| **both** | **107** | **137.3 MB** | **5.63 s** | **7.1x / 1.55x** |

The second lever is **not free**: it publishes which markets each maker serves.

---

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
| **default field + check** | **yes** | no | **+1 round, +6 KB** |
| **group order (253 bits)** | **yes** | **yes** | **2.14x clock, 14.3x traffic** |
| 177 bits + check | yes | no | 1.75x clock, 7.8x traffic |

**177 bits buys nothing the other two do not.** It was the answer to a question
that turned out to be badly posed --- the check runs in the narrow field, so
there is no reason to widen partway.

**Take the default field with the check** unless the publicly verifiable quote
proof is wanted, and take the group order when it is. The two mechanisms are
complementary rather than alternatives: the check says the inputs were the
committed ones and costs a round; the sigma assembly says the whole computation
was right and can be checked by anyone afterwards.

---

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

Measured at 120 ms one way --- Tokyo to Zurich --- with every arm verified. The
wall clock is an **inflated upper bound**: `host-a` carried a load average near
60 during the run. Rounds and bytes do not depend on load, and neither does the
round-trip floor computed from them, so both columns are given and they say the
same thing. The `Q=1` default-field figure of 26.7 s also matches
`placement_intercontinental.json`'s 26.1 s, so the instrument agrees with itself.

| | batch | rounds | MB a node | floor quotes/s | measured quotes/s | quote age |
|---|---:|---:|---:|---:|---:|---:|
| default field | 1 | 64 | 3 | 0.065 | 0.037 | 27 s |
| default field | 8 | 103 | 22 | 0.324 | 0.181 | 44 s |
| **default field** | **32** | **259** | **91** | **0.515** | **0.300** | **107 s** |
| matched field | 1 | 129 | 40 | 0.032 | 0.017 | 57 s |
| matched field | 8 | 399 | 323 | 0.084 | 0.033 | 245 s |
| matched field | 32 | 1314 | **1,276** | 0.101 | **0.036** | **889 s** |

**The matched field's round penalty grows with the batch.** It is 2.02x at
`Q=1`, 3.87x at `Q=8` and **5.07x at `Q=32`** --- rounds grow at **6.29 a quote**
in the default field against **38.23** in the matched one.

**So batching pays in the default field and does not in the matched one.**
Default: `Q=1` to `Q=32` takes 26.7 s a quote down to 3.3 s, eight times better,
while the age goes 27 s to 107 s, four times worse. Against `staleness.json`,
where 96 seconds is 1.34 to 1.75 times the within-block floor, that is a good
trade. Matched: 57.5 s to 27.8 s, twice better, while the age goes 57 s to
889 s, fifteen times worse. **A quote fifteen minutes old is not a quote.**

And 8,932 MB a job is **1,276 MB a node**, which a gigabit link spends ten
seconds a job moving.

**Cross-region, the matched field is usable only un-batched** --- 57 s a quote at
0.017 a second, which the staleness curve still tolerates. Batching it trades
age for throughput at about seven to one. **What runs cross-region is the default
field with the input check**: 0.300 quotes a second at a batch of 32 with a
107-second quote, and the binding costs one round.

---

## 9. Every prediction in this document that missed

Kept together rather than scattered, because a document that shows only the
predictions that landed is advertising a discipline rather than reporting one.

| predicted | measured | direction |
|---|---|---|
| matched field leaves the round count unchanged | **2.02x** --- an arbitrary prime does not get the comparison machinery the default field has | wrong |
| matched field costs about 2x traffic, from 16-byte elements becoming 32 | **14.3x** --- element width is the small half; comparisons over a general prime need far more shared bits | 7x too cheap |
| edaBits reduce it, since comparison should scale with value width | **150x worse** --- preprocessing measured in a single-phase harness | wrong phase |
| probabilistic truncation gives 150 to 250 MB | **no change at all** | wrong |
| the input check is free: one round and one field element | **true of the opening; the mask was not counted** | incomplete |
| the check therefore cannot run at 127 bits | **it runs** --- the first split of the budget that failed was taken for the whole budget | wrong |
| 2^-40 hiding is unreachable at 127 bits; then reachable with repetitions; then unreachable | **unreachable, ceiling about 2^-34** --- said three ways before the curve was tabulated | resolved by measuring |
| 177-bit field: 4--9x traffic, 96--129 rounds, 1.4--1.9x wall | **7.8x, 124, 1.71x** | all three landed |
| the check adds 1 to 3 rounds | **1** | landed |
| cross-region at a batch of 32: 347 rounds and 0.38 quotes/s, extrapolated from a 15 ms table by assuming the matched field's 2.02x holds at every batch | **1,314 rounds and 0.036 quotes/s** --- the penalty grows with the batch, 2.02x to 3.87x to 5.07x | 10x too generous |

Four in a row wrong, then two right, then one more wrong. Every one of them was
about arithmetic written down in this repository rather than about anything
inside MP-SPDZ, which is the part worth remembering: **the errors were in the
counting, not in the tool.** The last one is the sharpest example --- a ratio
measured at one batch size, assumed to hold at every batch size, and wrong by
ten times because the thing being extrapolated was itself growing.
