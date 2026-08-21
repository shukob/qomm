# Choosing a deployment

What every measurement implies for what to pick under which operating
conditions. The numbers come from `RESULTS.md` (through stage 3),
`OPTIMIZATION.md` (speed), `AUDIT.md` (audit, transport, proofs) and
`SURVEY.md` (comparison of schemes). **Estimates and measurements are marked
apart.**

---

## 0. The first decision: where the nodes sit

This matters more than any other choice. Measured (M=16, 31 bits, malicious
Shamir, N=7, T=2):

| node placement | one-way delay | one quote | RFS (k=5) update rate |
|---|---:|---:|---:|
| same rack | 0 ms | 0.166 s | 12.0/s |
| same metro | 1 ms | 0.617 s | 3.0/s |
| domestic wide area | 5 ms | 1.619 s | 1.2/s |
| Tokyo to Singapore | 15 ms | 3.876 s | 0.48/s |

Of the 3.68 s at 15 ms one way, **2.13 s is pure round-trip time** that no
circuit change touches. **Putting the seven nodes in one metro is six times
more effective** than any stack of cryptographic improvements.

Against that, putting them in one metro **raises the correlation of collusion**.
Seven nodes in the same jurisdiction and the same commercial orbit leave the
T=2 assumption resting on organisational independence alone, not geography.
That is governance, not technology, and it is an explicit trade against latency.

### 0.1 Independence cannot be bought inside a committee

The obvious compromise is six nodes in one metro and a seventh somewhere with a
different legal order --- geographic independence for the price of one node.
Measured at 120 ms one way, which is Tokyo to Zurich or Tokyo to London:

| node placement | one quote | vs all near |
|---|---:|---:|
| all near (1 ms) | 0.517 s | --- |
| **one far (six at 1 ms, one at 120 ms)** | **22.998 ± 0.733 s (n=3)** | **44x** |
| one near (six at 120 ms, one at 1 ms) | 25.682 ± 1.090 s | 50x |
| all far (120 ms) | 26.148 ± 1.209 s | 51x |

**One distant node costs 86% of what moving all seven costs**, against 82% at
15 ms (`placement.json`): the penalty for a single outlier grows with distance
rather than shrinking. The compromise is not a compromise. Every placement here
was verified against the plaintext answer.

The round count is what does this. It is 70, flat, independent of the number of
makers and of the number of assets, so the wall clock carries 70 x RTT of pure
waiting on whichever link is slowest.

*Prediction and miss, recorded.* 70 x 0.240 s = 16.8 s of round-trip plus about
1.5 s of computation predicted **~18 s**, from a model validated at 15 ms to
1.4% (predicted 2.10 s of RTT against the 2.13 s above). Measured **23.0 s**.
The linear model **under-predicts by 28%** at eight times the distance it was
checked at, so extrapolating it further should not be trusted either.

### 0.2 What 26 s is worth, which is not the same as how long it is

The table above says a globally spread committee is fifty times slower. It does
not say that matters, and the number that decides it is not the delay but
**whether the price moved during it.**

UniswapX fills carry a rate that really was executable at a block, so the drift
across a gap can be set against the dispersion the same market shows *within*
one block --- spread, size impact, fee tier, all the ways the price is not a
single number even at an instant. Ethereum blocks are about 12 s, so one
cross-region quote is two of them (`staleness.json`, four busiest pairs):

| gap | drift | vs the within-block floor |
|---|---:|---:|
| within one block | 4.8--7.5 bp | --- |
| **2 blocks, ~26 s: one cross-region quote** | 3.6--8.6 bp | **1.01x** (median) |
| 8 blocks, ~96 s | 7.4--9.4 bp | 1.34--1.75x |
| 25 blocks, ~300 s | 12.2--19.2 bp | 1.63--4.00x |

**Twenty-six seconds of drift is the same size as the price uncertainty the
market already has inside a single block.** A quote that took 26 s to compute is
not distinguishable from an instantaneous one, because the price was never that
precisely defined. And this is crypto on Ethereum L1 --- the harshest case
available. An instrument that moves less makes a slow quote cheaper, never
dearer, so this bounds the bond and derivative cases from above rather than
describing them.

Caveats, because the measurement has them: these are executed rates, so a filler
chose the moment; most blocks carry one fill, so the within-block series is 60
to 247 observations per pair; and the floor mixes spread with size impact rather
than being a quoted bid-ask.

**So the criterion is `drift(latency)` against the instrument's own price
uncertainty, and not the latency.** Where the spread is basis points, a
cross-region committee is affordable. Where it is a fraction of one, it is not.

### 0.3 What follows: the tier is per instrument

- **A committee spanning regions is available for request-for-quote**, at 26 s
  and with the geographic independence that a metro deployment cannot have.
  Where leakage hurts most --- wide spread, thin book, large size --- it is also
  where 26 s is cheapest. **The economics and the physics point the same way.**
- **Request-for-stream survives it better than request-for-quote does**, which
  is the opposite of what it looks like. A taker on a 26 s stream acts whenever
  they like, on a price 13 s old on average and 26 s old at worst, and waits for
  nothing. A taker on a 26 s request-for-quote waits 26 s and then acts on a
  price that is 26 s old. **Same drift, and the stream removes the round trip
  from the critical path.** The refresh rate falls; the mode does not fail.
  What a slow stream really costs is on the maker's side --- a quote up to 26 s
  old can be taken by someone watching a faster feed, so the maker widens by
  about the drift, which is the same 4.8--8.6 bp. On a five-basis-point
  instrument that roughly doubles the spread; on a fifty-basis-point one it
  disappears.
- **Crossing regions to settle was never round-bound anyway.** Two ledgers
  sharing no state settle through an adaptor signature and a deadline, costing
  0.06 ms of cryptography against an exposure set by the two ledgers' finality
  (`DEFMI.md` section 6).
- **A maker quoting outside its own region needs no committee spanning both.**
  Policy registration and quote computation are already separate: the rule
  crosses once, offline, where latency does not matter.

### 0.4 What a maker can decline

Every term in the price rule is a choice the maker makes, and all but one of
them were already declinable by setting a coefficient to zero: `slope` switches
off the size term, `invcoef` the inventory term, `active` the maker. The
reference price was the exception --- it was added with a hard-wired coefficient
of one, so a maker in a market with no usable benchmark had no way to say no,
and a corporate bond has no continuous mid to be an offset from.

`use_ref` is that missing switch: a secret bit per maker, with
`anchored = mid + use_ref * ref`. It puts one more multiplication into a SIMD
layer that already had two, so the depth does not move. Measured both arms in
one session on one machine (`use_ref_cost.json`, M=16, 31 bits, 4 assets, 15 ms,
both verified):

| | rounds | party0 | global | wall |
|---|---:|---:|---:|---:|
| without `use_ref` | 64 | 3.320 MB | 19.319 MB | 3.632 s |
| with `use_ref` | 64 | 3.328 MB | 19.369 MB | 3.625 s |

**Rounds unchanged, traffic +0.26%, wall clock inside the noise.** *Prediction
and miss:* rounds were predicted unchanged and are; traffic was predicted at
+1% to +3% and came in **five times cheaper**.

The two settings are two markets, and `qomm_dsl/examples/` now carries one file
for each. On the reference, `mid` is a small offset and the market level rides
along --- which is what section 0.5 is about. Off it, `mid` carries the level
itself, so it has to be declared wide enough to hold one, and a wider parameter
is a wider range proof: 12 bits round up to a 16-bit proof, 18 bits to a 32-bit
one.

**There is a cheaper version of the same switch, and it is worth knowing which
one is being bought.** Whether a market has a usable benchmark is a fact about
the market, not about the maker, and putting the switch there costs nothing at
all: a market with no benchmark is a **zero row in the public reference table**,
folded into a lookup that already happens. No field, no multiplication, no
bytes. What it gives up is that the venue decides rather than the maker.

The maker-side switch buys that choice, and pays for it twice: 0.26% of traffic,
and **the correction of section 0.5, whenever makers on one asset disagree.**
The correction works because the reference shifts every maker's cost equally and
so cannot reorder them --- which stops being true the moment some makers are on
the reference and others are not. A relative maker at `ref + 30` and an absolute
one at `100,020` swap places as the reference crosses `99,990`;
`tests/test_reference_invariance.py` holds the case.

So: **per-market is free and keeps the correction, per-maker costs 0.26% and
keeps the correction only while an asset's makers agree.** A venue that wants
both can take the maker-declared flag and require it to be consistent per asset
at registration, which is a rule about admission rather than about the circuit.

### 0.5 The drift need not be paid at all

The quote is affine in the reference price and the winner does not depend on it.
`anchored = mid + spread_request(ref)` adds the same term to every maker, and no
eligibility gate --- asset, size, expiry, active --- reads the reference, so a
move in it shifts every cost by the same amount and cannot reorder them.
`tests/test_reference_invariance.py` checks this rather than asserting it.

So a slow committee does not have to produce a stale quote. **Run against
whatever reference was current when the computation started, and correct the
revealed price by how far the reference moved in the meantime.** The winner
needs no correction; it was never wrong. The correction costs no rounds: it is
a secret one-hot vector times public constants, which is local, and with one
asset it is a public addition the taker can do unaided.

**This is a property the design has and the implementation does not yet use.**
`REF_TABLE` is fixed when the circuit is parameterised and an absolute price is
revealed, so today's output really is as old as the computation. Making it
current is a change to what is revealed, not to the circuit's cost.

Two things stay genuinely stale and are worth stating. The inventory term moves
when a maker trades rather than continuously, so it ages far more slowly than
the mid. And `expiry` is compared against the `now_t` the run started with, so a
policy expiring inside the window can be admitted wrongly --- evaluating expiry
against `now_t` plus the expected latency is the fix, and it costs nothing.

`REGULATION.md` section 5 takes up what each choice costs in trust, since a
regional committee and a spread one do not defend against the same adversary.

---

## 0.6 Running the MPC over the commitment's own field

The largest open problem in the stack is a field boundary. A maker's policy is
committed as a Pedersen commitment on ed25519 and shared to the nodes, and the
node can check its own share against that commitment before it computes
(`check_share`). What nothing forces is that the value the node then **inputs**
to MP-SPDZ is the value it was checked. Signatures make that detectable and
attributable afterwards; they do not prevent it.

Matching the MPC field to the curve's scalar order closes it, and the mechanism
is standard: Shamir reconstruction is a linear combination, so the nodes publish
`g^(share)` and Lagrange-combine in the exponent to `g^v` **without opening
`v`**, then check `g^v` against the commitment. That only works when the
exponent arithmetic and the MPC arithmetic are the same field.

Measured, both arms in one session on one machine, both verified against the
cleartext answer (M=16, 31 bits, 4 assets, N=7):

| | rounds | global traffic | wall @15 ms | wall @0 ms |
|---|---:|---:|---:|---:|
| MP-SPDZ `-F 128` | 64 | 19.4 MB | 3.626 s | 0.167 s |
| ed25519 scalar field (253 bits) | **129** | **277.3 MB** | **7.486 s** | **0.419 s** |
| ratio | **2.02x** | **14.3x** | **2.06x** | **2.50x** |

*Prediction and miss, twice.* Rounds were predicted **unchanged** and doubled ---
an arbitrary prime does not get the comparison machinery that the default field
has. Traffic was predicted at **about 2x**, from field elements going 16 B to
32 B, and came in at **14x**: the element size is only doubled, so the rest is
that comparisons over a general prime need far more shared bits.

**What the numbers say is that the price is round count and arithmetic width,
not transfer.** Fourteen times the bytes buys only two to two and a half times
the wall clock, and the ratio is *worse* at zero delay than at 15 ms, which is
the opposite of a bandwidth-bound cost.

Two things before treating 2x as the price of closing the gap. The seven parties
share one machine here and the delay proxy models latency but **not bandwidth**,
so 277 MB per quote --- about 40 MB per node, a third of a second on a gigabit
link and three seconds on a hundred-megabit one --- is a cost the measurement
does not show. And the 2x is paid **on every gate of every quote, forever**,
where the binding it buys is needed only when a value **enters** the system. A
policy is dealt once and priced against many times, so a per-input argument that
leaves the evaluation field alone would be paid at the dealing rate measured in
`maker_updates.json` (40 to 352 updates a second with commitments) rather than
on every quote. **Which of the two is cheaper depends on quotes per policy
update, and that ratio is a property of the market rather than of the protocol.**

### 0.6.1 Two hundred and seventy-seven megabytes is not deployable

So the matched field was taken as a starting point rather than an answer.

**edaBits made it two orders of magnitude worse.** They were the obvious first
try: comparison cost is supposed to scale with the value width rather than the
field width, which is exactly the 31-bits-against-253 mismatch that the traffic
is made of. Measured, `program.use_edabit(True)` gives **2,920 MB** on the
default field and **6,257 MB** on the matched one, against 19.4 and 277.3
without. The reason is not that the technique is bad: edaBits are preprocessing,
and this harness measures one phase, so the generation cost lands in the run with
no offline phase to hide in. That is the item section 4 already lists as the
largest unmeasured unknown --- **this measures the wrong phase for it**, and the
right measurement needs a preprocessing stage the bundled tool does not produce.

**Two levers already in the circuit halve it.** `audit_gates` moves the expiry
and active checks to the registration-time policy audit rather than paying for
the same fact twice; `public_maker_assets` makes the asset gate a public index
into a secret one-hot vector, which costs no communication at all.

| matched field, plus | rounds | global | wall @15 ms | vs default field |
|---|---:|---:|---:|---:|
| nothing | 129 | 277.3 MB | 7.39 s | 14.3x / 2.04x |
| `audit_gates` | 122 | 216.9 MB | 6.59 s | 11.2x / 1.82x |
| `public_maker_assets` | 123 | 197.7 MB | 6.53 s | 10.2x / 1.80x |
| **both** | **107** | **137.3 MB** | **5.63 s** | **7.1x / 1.55x** |

Predicted 150 to 190 MB, measured 137.3. The second lever is **not free**: it
publishes which markets each maker serves. All arms verified.

### 0.6.2 The field may not need matching at all

Binding the *dealt* shares to a commitment never needed a matched field. The
shares sum over the integers, so `g^v = prod g^(v_i)` holds in any group
whatever the MPC is doing. What needs matching is binding **what MP-SPDZ
ingested** --- and there is a cheaper way to get that.

The dealer already publishes a commitment per input. After the inputs are fixed,
derive public challenge coefficients by Fiat--Shamir over those commitments; have
the circuit compute `s = sum_j c_j v_j + r` for a committed mask `r`, and open
`s`; check `g^s` against the homomorphic combination of the commitments. A node
that substitutes an input shifts `s` by `sum c_j e_j`, which is non-zero except
with probability about `2^-40` over the challenge.

**The fields do not clash, and that is the whole point.** With 166 inputs of 31
bits and 40-bit challenges the sum is at most **79 bits**, which reduces in
neither the 127-bit MPC prime nor the 252-bit curve scalar field. It is the same
integer on both sides, so the check is exact across them.

The mask is not optional. Without it each quote opens one linear equation in the
policy, and enough quotes with fresh challenges solve for it --- the machinery is
already there, since the answer is opened under a trader-supplied mask.

**Predicted cost: rounds +1, traffic plus one field element.** Public coefficient
times secret is local, so the combination costs no communication, and one opening
is one round. That leaves the default field's 19.4 MB essentially unchanged
against 137 MB for the cheapest matched-field arm.

### 0.6.3 It was implemented, and it does not fit either

Written as `zk/input_check.py`, and the cryptography works: 27 tests, a
substituted input caught, two errors that try to cancel caught, coefficients that
move with the commitments. Cost on host-a over 166 inputs: **16.4 ms to build,
13.9 ms to verify** --- 204 scalar multiplications --- against 2.06x of a 3.6 s
quote for the matched field.

**The obstacle is the mask, and the arithmetic above missed it.** The opening is
120 bits and fits a 127-bit prime with seven to spare, which is what section
0.6.2 counted. But **119 of those 120 bits are the mask**, and the mask is an
input like any other: it is dealt to the nodes through
`qomm_transport.roles.split`, additively over the integers with `SLACK_BITS` of
room per share. That spends the forty bits **twice** --- once to hide the
combination in the opening, once to hide each share from its node --- and seven
shares of a 119-bit value need **164 bits of field**.

The 127-bit prime does not hold it at **any** coefficient width. Not at 32 bits,
not at 8, not at 3 where the check would be worthless anyway; the floor is
`124 + challenge_bits`.

| | field needed |
|---|---:|
| the opening alone (what 0.6.2 counted) | 120 bits |
| the opening plus dealing the mask | **164 bits** |
| MP-SPDZ default | 127 bits |
| group order, where `threshold_sigma` wants it | 253 bits |

**So the check does not avoid widening the field. It lowers the width from 253
to 164** --- and at 253 the same widening also makes `threshold_sigma` assemble
correctly, which 164 does not. The question is whether 164 is worth it over 253,
not whether the check escapes the problem.

*Prediction and miss.* Section 0.6.2 predicted "rounds +1, traffic plus one field
element" and called the fields "not clashing, and that is the whole point". The
opening does not clash. The mask does, and it was not counted. That is the fourth
prediction in this section to land on the wrong side, and the three before it
were about someone else's implementation --- this one was about arithmetic that
was written down here.

One thing the implementation did settle in the right direction: the width grows
with `log2` of the input count, so **covering a thousand times more inputs costs
ten bits**. What sets the floor is the mask, not the coverage, so one check over
everything is the right shape rather than one per maker.

### 0.6.4 Both halves, run and measured

The check needs about 165 bits and the sigma assembly needs the group order at
253, so the question was whether the narrower field is worth what it gives up.
Run at 177 bits --- the next prime above `2^176` --- with the check on and off,
against both ends, all four arms verified against the cleartext answer:

| | rounds | global | wall @15 ms | vs default |
|---|---:|---:|---:|---:|
| MP-SPDZ default, 128 bits | 64 | 19.4 MB | 3.635 s | --- |
| 177 bits, no check | 124 | 150.8 MB | 6.228 s | 1.94x / 7.8x / 1.71x |
| **177 bits, input check on** | **125** | **150.8 MB** | **6.377 s** | 1.95x / 7.8x / 1.75x |
| group order, 253 bits | 129 | 277.3 MB | 7.783 s | 2.02x / 14.3x / 2.14x |

**The check itself costs one round, no measurable traffic and 149 ms.** That is
what section 0.6.2 predicted before the mask was counted, and it holds --- the
prediction was wrong about where the check runs, not about what it costs once it
does. All four predictions for this run landed, after four in a row that did not.

**The narrower field buys 46% of the traffic and 20% of the clock**, at almost
the same round count.

### 0.6.5 Which one to take

**253, and the reason is not the arithmetic.** What 177 bits gives up is
`threshold_sigma` assembling, and that is what makes the quote proof publicly
verifiable --- the sigma responses combine across nodes by Lagrange *in the
scalar field*, so the shares have to be over the group order or the assembly
reconstructs the wrong thing. A publicly checkable proof that the returned price
was the minimum is the system's headline claim. Trading it for 126 MB is the
wrong way round when that is about 18 MB a node, which a gigabit link absorbs in
a seventh of a second.

So the shape of the answer:

- **128 bits**: fastest, and neither binding is available. The right choice only
  where the quote proof is skipped anyway and a substituted input is something
  to detect afterwards rather than prevent (`DEPLOYMENT.md` profile A).
- **177 bits**: the input check runs, one round. The sigma assembly does not.
- **253 bits**: both. 2.14x the clock and 14.3x the traffic of the default,
  and the check still costs one round on top.

The two mechanisms are complementary rather than alternatives, which is the part
that took four wrong predictions to see. The check says the inputs were the
committed ones and costs a round; the sigma assembly says the whole computation
was right and can be checked by anyone afterwards. **At 253 there is no reason
to choose between them.**

### 0.6.6 It does run at 128 bits, and 0.6.3 was wrong about why

Section 0.6.3 concluded the check needs 165 bits. That was about **one parameter
choice**, not about the field. The mask is
`value_bits + challenge_bits + log2(n) + statistical_bits` wide and the field has
to hold seven shares of it with forty bits of slack, so the budget is

    challenge_bits + statistical_bits <= 41

at 127 bits. Forty-bit coefficients leave one bit of gap and do not fit. **Six-bit
coefficients repeated seven times fit in 126 bits** --- and repetition is free in
rounds, because seven independent combinations wait on nothing and open together.

| | rounds | global | wall @15 ms | verified |
|---|---:|---:|---:|:---:|
| default field, no check | 64 | 19.37 MB | 3.583 s | yes |
| **default field, input check (6 bits x 7)** | **65** | **19.38 MB** | **3.631 s** | yes |
| 177 bits, input check | 125 | 150.84 MB | 6.377 s | yes |
| group order, no check | 129 | 277.26 MB | 7.783 s | yes |

**One round, six kilobytes, forty-seven milliseconds.** Soundness is `2^-42`,
which clears the `2^-40` the rest of the stack works to.

**What it gives up is the hiding of the opening, and that part is real.**
Repetition buys soundness back and dilutes the gap at the same time, so the curve
has a peak --- about `2^-34`, at two to four coefficient bits with eleven to
twenty-six repetitions --- and `2^-40` is out of reach at 127 bits anywhere on it.
The shipped setting sits at `2^-32`. `narrow_tradeoff` in `zk/input_check.py`
tabulates the whole curve, and a test holds the peak so it cannot drift.

So the field question resolves differently than 0.6.5 said:

- **128 bits with the check** binds the inputs for one round and six kilobytes,
  at `2^-32` hiding on the check's own opening. This is the answer for the
  deployment profiles that were going to skip binding altogether.
- **253 bits** additionally makes `threshold_sigma` assemble, which is what makes
  the quote proof publicly verifiable, for 2.14x the clock and 14.3x the traffic.
- **177 bits buys nothing either of those two does not**, now that the check runs
  in the narrow field. It was the answer to a question that turned out to be
  badly posed.

*Prediction and miss, again, and this one was mine twice over.* 0.6.2 predicted
the check would be free and did not count the mask. 0.6.3 counted the mask and
concluded the check could not run, without checking whether a different split of
the budget would fit. Both were arithmetic written down here. The measurement
that settles it took one run.

### 0.6.7 Three questions about the matched field, and one answer

**Would a different group make it cheaper? No, and this repository already
measured why.** The matched field's cost is set by the field *size*, and 128-bit
security forces a scalar field of about 256 bits for **any** discrete-log group,
elliptic curve or multiplicative. So no discrete-log scheme shrinks the MPC
field. What the group does change is the speed of the proofs, and there the curve
wins by a lot --- `zk_bench.json`, same host, same proof, seven fields and seven
parties:

| backend | prove | verify | share check |
|---|---:|---:|---:|
| ed25519 | 14.4 ms | 15.5 ms | 7.6 ms |
| modp multiexp | 4,865.6 ms | 7,358.6 ms | 1,419.0 ms |
| ratio | **338x** | **475x** | **187x** |

So a non-curve group is worse on one axis and neutral on the other. **The one
direction that could shrink the field is lattice commitments**, whose security
comes from dimension rather than modulus size --- a homomorphic lattice
commitment can live over a 32- or 64-bit modulus. What stops it is shape rather
than size: lattice sigma protocols need rejection sampling, so the response is
not a clean linear function of the witness, and `threshold_sigma`'s method ---
each node computes its own piece and they Lagrange-combine --- does not survive
that.

**What throughput does it leave cross-region?** Round counts do not depend on
machine load and a wide-area quote is round-trip bound, so this is computed from
measured rounds times the round trip rather than from a wall clock. Batching does
not amortise the rounds away: they grow at **3.48 a quote** in the default field
and **7.02** in the matched one.

| | batch | rounds | round trips | per quote | quotes/s | quote age |
|---|---:|---:|---:|---:|---:|---:|
| default field | 32 | 177 | 42.5 s | 1.33 s | **0.75** | 42 s |
| **matched field** | **32** | 347 | 83.2 s | 2.60 s | **0.38** | 83 s |
| matched field | 128 | 1021 | 245.0 s | 1.91 s | 0.52 | 245 s |

**Twenty-three quotes a minute**, and the ceiling is about 0.52 because rounds
grow with the batch. For cross-border request-for-quote in instruments that trade
by request in the first place, that is comfortable. **The binding limit is not
throughput but age**: a batch of 32 leaves a quote up to 83 seconds old, a batch
of 128 up to 245, against `staleness.json` where 96 seconds is 1.34 to 1.75 times
the within-block floor and 300 seconds is 1.63 to 4.00. Batches of 8 to 32 are
where the two constraints meet.

**And what does post-quantum cost?** The largest part of the answer is that
**the confidential computation is already post-quantum**: Shamir with an honest
majority is information-theoretically secure, so there is no assumption for a
quantum computer to break and the MPC layer needs nothing.

The next part is nearly as favourable. Pedersen commitments are **perfectly**
hiding and only computationally binding, so a quantum adversary can open a
commitment to a value it does not hold and can **never** learn the value. What
quantum takes away is the ability to prove, never the ability to hide.

What breaks is the signatures, the range proofs, the sigma protocols and the
quote proof, the one-of-many membership proof, and the adaptor signatures in the
cross-ledger settlement. For the signatures the cost is **size, not speed** ---
ML-DSA signs about as fast as Ed25519 in optimised implementations --- and the
maker update path is where the bytes land:

| signature | one full policy update | vs now | at 10 updates a second, 16 makers |
|---|---:|---:|---:|
| Ed25519 | 10,836 B | 1.0x | 0.19 MB/s |
| ML-DSA-44 | 159,264 B | **14.7x** | 2.83 MB/s |
| ML-DSA-65 | 215,271 B | 19.9x | 3.83 MB/s |
| SLH-DSA-128s | 501,732 B | 46.3x | 8.92 MB/s |

Fifteen times the bytes, and at rates a real market maker uses it is under three
megabytes a second. The sizes are the standard's; **no timing is claimed**,
because the only implementation available here is pure Python and its numbers
would not represent an optimised one.

**The proofs have no drop-in, and that is where the three questions become one**
(0.6.8 works this through, and 0.6.9 asks whether a quantum network changes it).
Post-quantum homomorphic commitments are lattice commitments, which is the same
direction that could shrink the matched field --- and the same rejection sampling
blocks both. Whichever reason takes you to lattices, the work that has to be done
is the same work: an assembly method that does not need the response to be linear
in the witness.

### 0.6.8 Post-quantum, in the detail the summary above skips

**Scope first, because the two halves of the stack are not in the same
difficulty.** There are two kinds of proof here, and only one of them has a
structural problem:

| | who proves | which proofs | what post-quantum costs |
|---|---|---|---|
| **single prover** | the maker, knowing its own secret | policy audit, state audit, range proofs, the input check | **size only** |
| **threshold-assembled** | seven nodes, about a value none of them knows | **the quote proof**, zkPI | **structural** |

`policy_audit.py` and `state_audit.py` do not import `threshold_sigma` at all ---
a maker proving something about its own policy needs no help. So the hard case is
the quote proof and zkPI, which is also the system's headline claim.

**Why the assembly works today.** A sigma response is `z = k + c*w`, which is
affine in the witness, so each node computes `z_i = k_i + c*w_i` from its own
share and the pieces Lagrange-combine into `z` with no node ever seeing `w`.
That is `node_response` and `combine_responses`, and it is the reason this design
uses sigma protocols rather than a general-purpose SNARK.

**Three obstacles under lattices, in increasing difficulty.**

**One, size.** A sigma proof here is `4,960 bytes` a step, measured
(`state_audit.json`). The lattice equivalents are kilobytes to tens of
kilobytes, depending on construction --- from the literature, not measured here.
That is bandwidth and nothing else; the design does not change.

**Two, rejection sampling.** A lattice response `z = y + c*s` leaks `s` unless
the prover sometimes throws it away and restarts, and that abort test is on the
**combined** `z` rather than on any share. So the nodes would have to
reconstruct `z` to decide --- and if the answer is "reject", they have already
leaked what the rejection existed to protect. Each retry needs fresh randomness
across all nodes, at an expected two to seven attempts. **A one-shot assembly
becomes an interactive protocol.**

**Three, shortness against Shamir, which is the structural one.** A lattice proof
is sound because the witness is *short*. Shamir shares are uniform in `Z_q` and
are not short, and Lagrange coefficients are arbitrary elements of `Z_q`. The
combination is literally

```python
z_value = sum(coefficients[p] * partials[p][0] for p in partials) % order
```

--- short things multiplied by large things and reduced. **Shortness does not
survive it.** This is not a parameter that can be tuned; it is a mismatch
between how Shamir reconstructs and what lattice soundness requires.

**Ways out, and their price.** *Replicated secret sharing* keeps shortness,
because reconstruction is a plain sum with coefficients in `{0,1}` --- at seven
nodes and `T=2` that is `C(7,2) = 21` shares in total with `C(6,2) = 15` held by
each party, so fifteen times the per-party storage and the multiplication cost
that follows it, and it does not scale past small `n`. *Sharing schemes with
small reconstruction coefficients* exist and trade against threshold
flexibility. *Threshold lattice signatures* are an active research area whose
known constructions are heavier than the plain scheme and need more rounds.

**So most of the stack goes post-quantum for a size penalty** --- 14.7x on the
maker update path, measured, and under three megabytes a second at rates a real
market maker uses --- **and the quote proof needs a construction this repository
does not have.** That is research rather than integration, and it is the same
research the matched field would need.

### 0.6.9 What a quantum network would change, which is one thing

**It closes the one place where this system's confidentiality is still
computational.** The MPC is information-theoretically secure --- there is no
assumption to break --- but the traffic between nodes runs over TLS. An
eavesdropper who records every link today and breaks TLS later holds every
share, and reconstructs. The computation is unconditional and **the pipe
carrying it is not**.

The deployment shape happens to be the one QKD can actually serve: seven fixed,
long-lived, known endpoints rather than arbitrary correspondents --- and section
0 already says to put them in one metropolitan area for latency, which is the
range at which QKD works.

**What it cannot do is one-time-pad the traffic.** Against measured volumes:

| | traffic a quote | key rate for a one-time pad |
|---|---:|---:|
| default field, 0.4 quotes/s | 19.4 MB | **62 Mbps** |
| default field, 3 quotes/s | 19.4 MB | 465 Mbps |
| matched field, 0.4 quotes/s | 277.3 MB | 887 Mbps |

Metro-scale QKD produces roughly 0.1 to 10 Mbps (literature, not measured here),
so even the cheapest row is one to two orders of magnitude short. What a
deployment would actually do is rekey a symmetric cipher often --- **and
symmetric ciphers are already quantum-safe**, since Grover only halves the
effective key strength and AES-256 absorbs that. **So the real gain is narrower
than it sounds: not having to trust the key-exchange assumption.** Against
store-now-decrypt-later that is still a genuine defence.

**Where it does not help, and not for practical reasons.** Unconditionally
secure bit commitment is **impossible even with quantum mechanics** (Mayers;
Lo--Chau, 1997). Quantum does not rescue the commitments, so the lattice work
above is not avoidable by building a quantum network instead.

The reason generalises to the rest: **a proof has to convince someone who was
not on the link** --- an auditor, a supervisor, a counterparty checking years
later. QKD secures a channel between two parties who are both present. Quantum
digital signature schemes exist but need quantum memory or repeated
distribution, and their transferability is limited, so they do not give
"anyone can verify this afterwards" either. Signatures still need ML-DSA or its
kind.

| | does a quantum network change it |
|---|---|
| the MPC layer's security | no --- already unconditional, nothing to improve |
| **confidentiality of the inter-node traffic** | **yes --- this is the one** |
| commitments | no, and by a no-go theorem rather than by engineering |
| the quote proof | no --- it has to convince someone who was not there |
| signatures | no --- they have to be transferable and checkable later |

Two further ideas that sound closer than they are. *Quantum secret sharing*
would distribute shares over quantum channels with eavesdropping detection, but
the shares here are classical values, so the benefit collapses back into the
row above. *Anonymous transmission* through entanglement would hide which
participant sent a request --- the transport layer's job, approximated today by
batching and shuffling on a fixed schedule --- and is theoretically stronger and
practically remote.

**The line worth keeping: a quantum network makes the pipe unconditional, not
the proof.** And the proof side has an impossibility result sitting on it, so
the work in 0.6.8 stays on the list either way.

## 1. Three deployment profiles

The measurements narrow the realistic choices to three.

### Profile A: metro, no audit, latency first

| item | setting | why |
|---|---|---|
| node placement | same metro (1 ms one way) | 0.617 s per quote |
| bit length | 31 | 42% less traffic, enough for prices around 100,000 ticks |
| tournament | binary | raising the arity does not change the wall clock |
| batch Q | matched to the arrival rate (Q=3 for a one-second slot) | rounds belong to the job |
| proofs | **no** quote proof | avoids +550 ms to complete the proof |
| disclosure | threshold disclosure (arm B) | DP disclosure measured significantly worse |
| protocol | malicious Shamir | 1.12 to 1.24x the wall clock over semi-honest. Cheap |

**What it gives**: sub-second quotes, secrecy for requests that do not settle
(AUC 0.500).
**What it does not**: a proof that the computation was right. Receipts bind a
node to a result; they do not show the result was correct.

### Profile B: metro, audited, near-immediate

| item | setting | why |
|---|---|---|
| node placement | same metro (1 ms one way) | |
| proofs | quote proof, M <= 16 | 317 ms to prove, 400 ms to verify |
| the three times | priced 824 ms, proved +551 ms, settleable +655 ms = **2.03 s** | measured |
| RFS update interval | set it to **3 s or more** | one second is not met (measured) |
| disclosure interval | 60 s | proofs and audits fit comfortably |

**What it gives**: the computation is verifiable every slot, and the joint proof
means no node holds the witness.
**What it does not**: a sub-second settleable time, or a one-second RFS.

### Profile C: wide area, batched

| item | setting | why |
|---|---|---|
| node placement | geographically spread (15 ms one way) | when governance independence comes first |
| batch Q | 16 to 32 | 284 ms per quote at Q=32 (measured) |
| one user's wait | 9.09 s at Q=32 | the whole job's duration |
| suited to | markets that value secrecy and dispersion over immediacy | |

**Choosing Q**: time per quote falls monotonically as `T(Q)/Q` while the wait
rises as `T(Q)`. At an arrival rate of lambda per second and a slot period of
`S` seconds, `Q ~ lambda*S` fills naturally. Measured at 15 ms one way,
`T(Q) ~ 3.4 + 0.18Q` seconds for Q <= 32, so for a target wait `W` take the
largest Q with `Q <= (W - 3.4)/0.18`.

---

## 2. Choosing each component

### 2.1 Anonymous credentials (KYB)

| registry size | what limits it | choice | measured basis |
|---|---|---|---|
| N <~ 8 | proving, on the maker's device | **OR composition** | 1.21 ms to prove at N=8 |
| N >~ 16 | verifying, at the venue or on chain | **Groth-Kohlweiss** | 2.35x faster to verify and 5.1x smaller to prove at N=128 |
| attributes to hide too | anonymity set | BBS+ family (not built) | re-randomisable |

Today's cohort registry holds a handful to a few dozen firms, so **OR
composition is the default**. If the venue starts verifying many presentations
per slot, swap in `zk/gk_oneofmany.py`; the two share the group abstraction, so
the change is local.

### 2.2 Range proofs

This implementation (bit decomposition) **does not get faster in batch** ---
2.9 ms each, flat, measured. Bulletproofs in the literature reach 0.24 ms per
range in batch verification and 74 us with aggregation. So:

| use | how many | choice |
|---|---|---|
| maker policy audit, at registration | 6 fields | **this implementation is enough** (15.9 / 15.4 ms, negligible against a 60 s disclosure interval) |
| proving a quote correct | M of them, dominant at M=16 | **replace with Bulletproofs** (not built; verification expected to fall by an order of magnitude) |

That last effect is **an estimate, not a measurement**. Building it and
measuring it is the next piece of work.

### 2.3 Verifiable DP

Of D1 to D4 in `SURVEY.md` section 4, **D1+D2 are the default**, D3 is a future
extension and D4 is not taken. The reasons are a mismatched threat model --- D4
assumes a single prover that knows the plaintext aggregate --- and a cost two
orders of magnitude apart.

**But DP disclosure itself is not recommended at present.** It measured
significantly worse than no disclosure at all (fill rate -0.039, maker P&L
-100.7, both beyond the minimum detectable difference). The cause is identified
as upward bias in a non-linear statistic, so **arm B stays the default until a
bias correction is added and the measurement repeated**.

### 2.4 Threat model

| | rounds | traffic | wall clock |
|---|---|---|---|
| semi-honest Shamir | 82 | 3.79 MB | 3.83 s |
| malicious Shamir | 100 | 12.16 MB | 4.73 s |

**Malicious security costs 1.12 to 1.24x the wall clock and 2.9 to 3.2x the
traffic.** At that price, requiring it is a reasonable call and there is no
reason to drop it.

### 2.5 Multiple assets

**The round count does not depend on the number of assets** --- 70 rounds flat
from 1 to 32 assets, measured. Only traffic grows, by about 0.04 MB per asset.
**There is no reason to split the job per market.**

Settling in the clear reveals the market from the asset that moves, so hiding
the market only means something together with the settlement side. zkPI
(section 2.6) is what fills that.

### 2.6 zkPI: closing the settlement side

Making the payment instruction itself a commitment and a proof lets the
settlement venue confirm only that it is a valid, unspent instruction that
matches the rules, without reading the asset, the quantity, the price or the
counterparties. Measured on Ed25519:

| | measured |
|---|---:|
| issuing an instruction (range proofs plus quorum signature) | 11.8 ms |
| verification at the venue | 12.6 ms |
| nullifier | 32 B, hides the legal entity |

**This carries the market selection hidden inside the MPC all the way through
settlement.** The venue needs only `verify` and the nullifier, so **it drops
into another DEX unchanged**: it never needs to know how the price was reached.

Implication: if multiple assets are in scope, take zkPI with them. Combined with
plaintext settlement, the secrecy paid for in the circuit is lost at settlement.

### 2.7 The width of a settlement rail

DeFMI's settlement cost is set almost entirely by **the ledger's balance
width**, not by the choice of cryptography. Measured (`DEFMI.md`): 0.44 ms/bit
to build, 0.55 ms/bit to verify, 448 B/bit on the wire. At 40 bits, 26.1 ms of
the verification is zkPI itself and does not depend on the width.

| decision | choice | effect |
|---|---|---|
| securities rail width | from the largest quantity to be listed; 24 bits is 16 million units | 48 to 32 bits cuts verification 12% and 5,376 B |
| cash rail width | the settlement currency's smallest unit times the expected ceiling; 40 bits is 1.1 trillion | as above |
| same width for both? | **no** | securities and cash are orders of magnitude apart |

This is the only lever that works without changing a line of cryptography. It is
a listing decision, not a technical one.

**The Rust implementation blunts this lever.** Bulletproofs comes only in powers
of two, so securities at 24 bits round up to 32 and cash at 40 to 64 (section
2.12). Trimming the width is fully available only in the Python implementation.

### 2.8 Hiding the instrument at the settlement layer

The MPC layer hides which market a request is for (`multi_asset.json`: 70 rounds
flat from 1 to 32 assets). Dropping onto a per-instrument rail at settlement
gives that back, so hiding it means using an asset tag.

| choice | when | cost |
|---|---|---|
| per-instrument rails | a venue where the instrument is public (listed equities) | zero, but the instrument leaks to the settlement layer |
| asset tags | where the instrument is itself information (block trades, private placements) | +32 B and +1.7% to build per settlement at 64 instruments; 20.3 ms / 1,344 B for the membership proof at issue |

The tag's soundness rests on the range proof on the difference. Neither a
registered tag for a different instrument nor a point that was never registered
can move a balance (both measured as `rejected`). The membership proof is needed
**only when a balance is issued**.

### 2.9 How far to take netting

| decision | choice | effect |
|---|---|---|
| gross or net, per rail | gross if failure is not tolerable, net to get the liquidity | gross is order dependent and refuses; net can fail at the close |
| instruction granularity | one zkPI per trade, or one attestation per cycle | per trade takes 12.6 s to verify at N=256; per cycle takes 0.2 s (**67.7x**) |
| how far net may go | the risk the FMI takes on, capped by collateral after haircut | the coverage proof costs the same either way (9.2 to 9.2 ms), and the sign is hidden too |
| waterfall tranches | four, as in practice | about 9.1 ms per tranche, run once per default |

**Checking at the order and checking at the close are a trade.** A gross rail
removes settlement failure by construction, but a participant receiving 100 and
delivering 100 is refused when the delivery arrives first --- which is exactly
the liquidity saving netting exists for. Practice answers with a limit; the Bank
of Japan's intraday overdraft is that answer.

Collapsing the instruction to one per cycle makes the settlement layer's work
independent of the number of trades, but individual trades are then no longer
verified. Conservation and coverage remain, and each participant can check its
own net, so what is lost is **third-party verifiability of the allocation**.
That is what a central counterparty has always been; this only makes it
explicit.

### 2.10 Hiding the counterparties (the note ledger)

An asset tag hides only *what*. With fixed handles, *who with whom* remains. A
note ledger buys an anonymity set sized by the ring, but the cost is
**asymmetric**.

| ring size | prove (payer) | verify (node) | wire |
| ---: | ---: | ---: | ---: |
| 8 | 19.5 ms | 22.8 ms | 19,232 B |
| 64 | 32.1 ms | 27.2 ms | 19,904 B |
| 512 | 159.3 ms | 56.3 ms | 20,576 B |

A settlement node handles a ring of 512 in 56.3 ms. What binds is the payer's
159.3 ms. So the ring size is set by **the payer's device**, and 64 (32.1 ms to
prove) is the sensible mark.

Putting a whole DvP on note rails, against 68.3 ms for the account version:
68.8 ms at ring 2 (+1%), 72.8 ms at ring 16 (+7%), 80.8 ms at ring 64 (+18%).

| decision | choice | effect |
|---|---|---|
| accounts or notes | notes when the counterparty relation is itself information | +1% to verify at ring 2, +18% at ring 64; counterparties narrow to the ring |
| ring size | the largest the payer's device tolerates | the wire grows only 224 B per doubling, so bandwidth does not decide it |
| pool size | the scan cost falls on the payee | 0.052 ms each; 5.2 s per scan over 100,000 |

Only the sender can tell that a note they made was spent, because they know the
`g^S`. That is unavoidable in this construction, so hiding it from the sender
needs one intermediate move.

### 2.11 Relays

| hops | slot wall clock | origin-linking AUC |
|---|---:|---:|
| 1 | 34.7 ms | 0.500 |
| 2 | 38.3 ms | 0.500 |
| 3 | 43.5 ms | 0.500 |

**About 4.4 ms per hop.** Every hop on the path must be compromised to follow a
message, and that gets harder with each one. A single hop lets the relay see the
user's IP, so **two or more is recommended**. The cost is negligible.

### 2.12 Which implementation runs the settlement layer

Measured on the same machine (`DEFMI.md` section 7). A 40-bit rail rounds up to
64 under bulletproofs, so the comparison is made on the rounded-up side.

| | Python (bit decomposition) | Rust (Bulletproofs) |
|---|---:|---:|
| settle (verify) | 48.8 ms | **7.79 ms** (6.3x) |
| package | 29,523 B | **2,816 B** (10.5x) |
| per core | 20.5/s | **128/s** |
| rail width granularity | any (24 and 40 bits included) | 8/16/32/64 only |
| audit of the underlying cryptography | none (hand-rolled over libsodium) | dalek and bulletproofs (Quarkslab 2019), FROST (NCC 2023) |
| DvP on note rails | present | **absent** (not ported) |

**Deploy the Rust.** The Python implementation stays as the measuring
instrument and as the way to trim widths freely for design decisions. A
deployment that uses note rails, though, exists only in Python so far.

---

## 3. What has to be decided before deployment, and is not decided by technology

1. **Independence of the node operators.** T=2 tolerates two colluding nodes.
   Placing them in one metro gives up geographic independence, so operator,
   jurisdictional and corporate-parent independence has to carry it instead.
2. **The size of the bond.** The slashing that is implemented carries only
   relative weights --- 1,000,000 for a double signature, 500,000 for an
   omission, 250,000 for stale state, 50,000 for a missing receipt. The absolute
   figure follows from an estimate of what misbehaving could earn.
3. **The target RFS update interval.** With auditing, set it to 3 s or more.
   Requiring one second means choosing between a lighter proof (replacing the
   range proofs with Bulletproofs) and dropping the audit.
4. **A per-entity cap.** About ten probes recover a maker's inventory, so this
   cap is the only defence. Tightening it also constrains legitimate users; the
   measured probe counts are what to set the level from.
5. **What the settlement venue will accept.** zkPI's `InstructionBounds` --- the
   floor and ceiling on quantity and price, and the deadline horizon --- are the
   venue's to publish. Narrow is safer and also refuses legitimate trades. That
   is venue policy, not technology.

---

## 4. Unverified, and still bearing on the deployment decision

| item | state | bearing |
|---|---|---|
| offline/online separation | **not measured** (the bundled tool does not produce malicious-Shamir preprocessing) | if preprocessing can run between slots the online rounds could fall further. **The largest remaining unknown** |
| a real seven-site deployment | measured to two sites (real RTT 17.4 ms, 1.66 s net) | operating and recovering seven sites is unknown |
| disclosure halt rate in a thin market | unverified | if arm B always withholds in a thin market, the choice of disclosure changes |
| reproduction on other data | unverified | the stage-3 conclusions stand on generated data |
| the effect of replacing with Bulletproofs | **measured** (Rust, `artifacts/rust_bench.json`) | 10.5x on the package, 6.3x on verification, at the price of widths fixed to powers of two |
| the fixed cost of a quote | **measured** (`OPTIMIZATION.md` section 3.7) | 406 to 31 ms per quote at 0 ms one way, but the split is 9.8x from batching and 2.0x from residency, so **a resident service is not needed outside a low-latency deployment** |
| keeping the MPC party processes resident | not built (needs TLS certificates) | the fixed cost that remains is 5.3 ms per quote at Q=32; it only matters at Q=1 |
