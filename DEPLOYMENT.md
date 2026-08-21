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
