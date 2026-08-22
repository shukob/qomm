# What happens when a node misbehaves

`POSITION.md` lists two gaps in one line: *no accountability and no robustness*.
That line is accurate and it is also lazy, because the two are different
properties, they sit at different rungs of a ladder that has five of them, and
in this deployment they have very different prices. One of them turns out not to
be a price at all.

Every figure here is measured on `host-a` at `n = 7`, `T = 2`, 128-bit field
(`artifacts/multiplication_cost.json`).

---

## 1. The ladder, which is five rungs and not two

Take a protocol where one of the seven nodes deviates. What can the rest of the
world end up knowing?

| | what it gives | needs |
|---|---|---|
| **1. security with abort** | the output is right, or there is no output | dishonest majority is fine |
| **2. identifiable abort** | ...and the honest parties learn *who* | dishonest majority is fine |
| **3. publicly identifiable abort** | ...and so does anybody reading the transcript | a bulletin board |
| **4. public accountability** | ...and a *judge* reaches a verdict from the transcript alone, naming enough parties to explain the abort | a bulletin board |
| **5. robustness / guaranteed output delivery** | there is no abort. The honest parties get the output whatever the corrupt ones do | **honest majority** |

**Public verifiability is not on this ladder.** It is the orthogonal axis: *the
answer is right, and an outsider can check it*. That is what Baum–Damgård–Orlandi
2014 gives and what this stack has. A protocol can be publicly verifiable and
still stop dead at rung 1, which is exactly the situation here.

So the honest statement of the gap is: **this stack is publicly verifiable and
sits on rung 1.**

### Where the rungs come from

**Rung 2** is Ishai, Ostrovsky and Zikas (CRYPTO 2014), and their framing is the
part worth keeping: identifiable abort exists *because* a dishonest majority
rules out rung 5. When a single malicious party can force an abort, the best
available consolation is to make aborting cost the adversary its anonymity. They
also prove a limit --- information-theoretic identifiable abort is impossible in
the OT-hybrid model, so pairwise correlated randomness is not enough.

**Rungs 3 and 4** are the difference between *the other parties* knowing and
*the world* knowing. Küsters, Truderung and Vogt (CCS 2010) supply the object
that makes rung 4 precise: a **judge**, an algorithm that takes the public
transcript and returns a verdict. Rivinius et al. strengthen it to *strong*
accountability --- on abort, name not one party but at least as many as it takes
to cause an abort, so a single scapegoat is not a valid verdict.

**Rung 5 needs an honest majority and is therefore not available to most of this
literature at all**, which is why almost everything in the auditable-MPC line
lives on rungs 1 to 4.

---

## 2. Where this stack actually sits

Three mechanisms, three different rungs, and it is worth separating them because
the repository has previously described all three as "attribution".

**The dealt share: rung 4, and only at the boundary.** `qomm_transport/roles.py`
has the maker sign each dealt share, so a node that later claims a different
share can be shown to have done so, by anyone. That is a judge-checkable verdict
--- rung 4 --- but its scope is one message, not the protocol.

**What the node feeds the engine: rung 0.** Nothing. This is the gap `BINDING.md`
is entirely about. A node can check its share against the commitment and then
put something else into MP-SPDZ, and the transcript does not show it.

**The MPC itself: rung 1.** `malicious-shamir-party.x`, and MP-SPDZ's own README
is explicit about what that word buys:

> malicious means that not following the protocol will at least be detected

Detected. Not attributed, not survived. The protocol stops and nobody is named.

**And the quote proof is on the other axis entirely.** It shows the winner was
the minimum of the committed keys. If it fails, you know the answer was wrong.
You do not know which node made it wrong, and you do not have an answer.

---

## 3. Robustness is not a cost here. It is a saving.

This is the finding, and it took a measurement to see because "what it costs" is
a claim about a baseline, and the baseline that matters is the engine that is
actually deployed rather than the one a paper compares against.

**The setting is better than it looks.** `T = 2` of `n = 7` is `t/n = 0.286`,
which is below `n/3`. Goyal, Song and Zhu (CRYPTO 2020) give unconditionally
secure MPC with guaranteed output delivery for `t < n/2` assuming a broadcast
channel, **and note that at `t < n/3` broadcast can be simulated over
point-to-point links**. So this deployment is in the stricter of the two regimes
and needs no broadcast channel assumed --- and in any case the bulletin board
that publicly auditable MPC already requires would serve as one.

Their price for that: **5.5 field elements per party per multiplication in the
best case, 7.5 once a corrupted party has been identified**, against 5.5 for the
best semi-honest protocol. Hence the title, *Guaranteed Output Delivery Comes
Free in Honest Majority MPC*.

**Free against what?** Measured here, same host, same parameters, as a slope
between two circuit sizes in one SIMD row:

| | elements per party per multiplication | rounds |
|---|---:|---:|
| semi-honest Shamir, single phase | 5.714 | 4, flat |
| **malicious Shamir, online phase only** | **8.000** | 3, flat |
| **malicious Shamir, single phase (triples generated in the run)** | **48.231** | 17 → 137 |
| **GSZ 2020, guaranteed output delivery, single phase** | **5.5 to 7.5** | --- |

**Guaranteed output delivery costs less than the online phase alone of what is
deployed**, and 6.4x less than its total --- while giving strictly more, because
it does not stop. GSZ is single-phase and information-theoretic: there is no
offline phase to move off the critical path, so 5.5 is everything.

**So the reason this deployment has no robustness is the engine, not the
setting.** MP-SPDZ's honest-majority malicious protocols --- Shamir, Rep3, PS,
SY, Rep4 --- are all secure with abort, and GSZ is not implemented in it. That is
a very different kind of gap from "we chose a threat model that cannot have it".

### The instrument was checked before it was believed

The harness was built for a different question, so its semi-honest arm is a
control against a number it was not fitted to: **GSZ state the best known
semi-honest protocol at 5.5 elements per party, and the harness returns 5.714**
--- four per cent, on a figure from a paper. A control circuit with the
multiplications replaced by additions has slope zero, confirming that the input
sharing and the single opening do not scale with the size and so are not inside
the slope.

### Two mistakes this measurement nearly repeated

**The first version measured 48.2 elements and 22,002 rounds for 22,000
multiplications.** It was running a sequential `for_range`, so every
multiplication sat on the critical path and paid its own round. That is a real
quantity and it is not a per-multiplication cost; the quote circuit batches, and
so does the corrected program, which holds at 3 rounds from 2,000
multiplications to 220,000.

**And the phase split is recorded separately on purpose.** Measuring
preprocessing in a single-phase harness and calling it an online cost is an error
this project has already made once, with edaBits, where it produced a figure two
orders of magnitude wrong. Here both numbers are kept: 48.2 total, 8.0 online.
The comparison to GSZ uses the total, because GSZ has no offline phase --- but
the online figure is what a deployment with real preprocessing would pay, and
conflating them would flatter the wrong side.

---

## 3.5 "Just put GSZ into SPDZ" --- three reasons that is not the move

**It is not a thing that can be done, in the literal sense.** SPDZ is a
*dishonest majority* protocol: MACs on every share, offline/online, secure
against `n-1` corruptions. GSZ is an *honest majority* protocol: Shamir,
information-theoretic, and its guarantees exist **because** `t < n/2`. Putting
one inside the other is not an integration; the guarantee GSZ provides is
unavailable at SPDZ's corruption threshold at all.

The sentence that does typecheck is *"add GSZ to the MP-SPDZ framework as
another honest-majority protocol"*, alongside `shamir-party.x` and
`malicious-shamir-party.x`. **This stack does not use SPDZ.** It uses the Shamir
protocols that happen to ship in the same repository.

**Even stated correctly it is not a protocol plugin.** MP-SPDZ's protocol
interface is `init_mul / prepare_mul / exchange / finalize_mul` over a fixed
party set moving forward. GSZ needs three things that interface does not have:
the circuit cut into **segments with checkpoints** so a failure re-runs a segment
rather than the run; a **party set and threshold that change mid-computation** as
parties are eliminated, which forces re-sharing of the segment's inputs; and an
asymmetric **king with relays**. That is a change to the virtual machine, not a
new class beside the existing ones.

**And it would not deliver accountability.** GSZ's identification is towards the
other parties. Section 4.

---

## 3.6 What is available without any of that: the shares are already an error-correcting code

Reading `Protocols/MaliciousShamirMC.hpp` makes the current behaviour concrete.
On an opening, each party sends its share; the receiver reconstructs from
`t+1` of them, then reconstructs again from every longer prefix and compares:

    if (check != value)
        throw mac_fail("inconsistent Shamir secret sharing");

**That is error *detection* performed on data that supports error
*correction*.** Shamir shares of a degree-`t` secret are a Reed--Solomon
codeword `RS[n, t+1]`. At `n = 7`, `t = 2` that is `RS[7, 3]`, minimum distance
`5`, and the number of errors correctable is `floor((5-1)/2) = 2` --- **exactly
`T`**. Berlekamp--Welch would return both the correct value *and* the error
locator, which names the parties that sent wrong shares. Local computation, no
extra rounds.

**Two things stop this being a free lunch, and they are worth stating precisely
because they are what GSZ is a paper about.**

**One: the opening only collects `2t+1` shares.** `finalize_raw` does
`shares.resize(2 * threshold + 1)` --- five of seven. `RS[5, 3]` has distance
`3` and corrects one error, not two. Correcting `T = 2` needs all seven, which
is `n` instead of `2t+1` shares per opening: **40% more opening traffic**, and
that is the price, not zero.

**Two: products are degree `2t` before reduction.** A degree-`4` sharing over
seven points is `RS[7, 5]`, distance `3`, one correctable error. So the
correction capability is `T` on ordinary values and `T-1` on unreduced products,
and a protocol that wants robustness has to avoid ever needing the second ---
which is what GSZ's segmenting and re-sharing machinery is for.

**So the honest summary is: robust *reconstruction* at `t < n/3` is a local
decode plus 40% on openings, and robust *computation* is GSZ and is a bigger
job.** The first is worth doing on its own --- it removes the cheapest griefing
attack --- and nothing in this repository has measured it.

### Asked directly: is it known who cheated? No --- and the obvious guess is wrong

Four runs on `host-a`, one byte flipped in one party's preprocessing file, `-F`,
restore between runs (`artifacts/locate.json`):

| corrupted party | what the transcript says |
|---|---|
| 3 | `Fatal error at fp2000-0:3 (MULS): inconsistent Shamir secret sharing` |
| 1 | **identical** --- the `3` is the instruction offset, not the party |
| 5 | `Fatal error in communication: read_some: stream truncated` |
| 6 | `Fatal error in communication: read_some: stream truncated` |

**The first two lines settle it**: the same string for two different culprits, so
the transcript carries no party information. **The last two are worse than
nothing.** When the bad data belongs to a party the others reach later, they die
on a dropped connection first --- so the attribution a reader would naturally
reach for, *whose link went down*, points at whichever process exited first
rather than at the party whose data was wrong. **An operator debugging this would
blame the wrong node.**

### And it is decidable, on data the protocol already sends

`qomm_audit/locate.py` is the decode MP-SPDZ does not do, with 26 tests.
Berlekamp--Welch: solve for `Q` of degree `<= d+e` and monic `E` of degree `e`
with `Q(x_i) = y_i E(x_i)`, then `P = Q/E` is the true polynomial and every share
off it belongs to a liar.

| | capacity | 0 wrong | 1 | 2 | 3 |
|---|---:|---|---|---|---|
| degree-`t` (ordinary value) | **2** | 300/300 | 300/300 | **300/300** | 0/300 |
| degree-`2t` (unreduced product) | **1** | 300/300 | **300/300** | 0/300 | 0/300 |

*named exactly, out of 300 random trials each*

**`T = 2` and the capacity is 2. That coincidence is the finding** --- this
deployment's corruption threshold sits exactly at the decoding capacity of its
own sharing, so every corruption it is designed to tolerate is also one it could
name. At three the decoder refuses rather than guessing, which is the only
correct behaviour: naming somebody beyond capacity would be worse than silence.

Cost, on data already received, no extra rounds:

| | median |
|---|---:|
| plain Lagrange from 3 of 7, which is what the engine does | 20.6 us |
| locate, no errors | 22.9 us |
| locate, one liar | 88.4 us |
| locate, two liars | 208.1 us |

### And it is now in the engine

`rust/qomm-mpc/patches/locate-inconsistent-shares.patch`, built and run on
`host-a` (`artifacts/decode_patch.json`). Same experiment as above, one byte
flipped in one party's preprocessing:

| corrupted | what the transcript now says |
|---|---|
| P0 / P1 / P3 / P5 / P6 | `... sent by player 0` / `1` / `3` / `5` / `6` |
| {1,4} | `... sent by player 1, player 4` |
| {0,2,5} | `more than 2 parties sent wrong shares, which is beyond the decoding capacity of this sharing` |

Honest runs return the same answer as before. Three liars are refused rather
than guessed at, which is the only correct behaviour past capacity.

**The traffic cost, and the prediction it broke.** `ShamirMC::exchange` is a
*partial* broadcast: with `threshold` set to `2t` it makes each party a sender
to the `2t+1` nearest and no further --- exactly enough to reconstruct a
degree-`2t` sharing and exactly one share short of locating two liars in a
degree-`t` one. So the patch also has to widen the broadcast, and each party
goes from four correspondents per opening to six.

| | before | after | |
|---|---:|---:|---|
| online, elements per party per multiplication | 8.000 | **12.000** | **1.50x** |
| single-phase total | 48.235 | **64.236** | **1.33x** |
| rounds | 3 / 11--23 | 3 / 11--23 | unchanged |
| per quote at `M=16`, global | 17.89 MB | **23.83 MB** | |

**The prediction said this would be free**, on the reading that
`ShamirMC::POpen_Begin` calls `P.send_all()` so every share was already on the
wire. That is the *unbatched* path. The batched one is `exchange`, and it is
what runs. **Third time in this project that reading one code path and assuming
it is the one that executes has cost a number** --- after the `-P`/`-F` compile
flag and after predicting MASCOT's online phase from what Shamir does here.

### The half of the answer that is not free

**This names the party that sent a malformed share. It cannot name the party
that lied about its input**, and that is the more likely attack.

`secret_input()` sums one additive share from each party, so a party that writes
a different number into its own input file is offering a **valid sharing of a
different value**. Nothing is inconsistent. There is no codeword to decode,
because the codeword is fine --- it encodes the wrong secret.

That is the gap `BINDING.md` is about, and the input check detects it without
naming anybody: *"an input the circuit used was not the one that was
committed"*. **Turning that into a verdict means opening one combination per
party rather than one over all inputs** --- `n` openings and `n` masks instead of
one, and the masks are what forced the 164-bit field in the first place.

### And the dealer already publishes what would name that one too

`qomm_transport.roles.Dealing` carries **`share_commitments` --- one commitment
per share per value** --- so that a node can run `check_share` on what it was
handed and anyone can run `adds_up` on whether the shares sum to the committed
value. Those are exactly the commitments a per-party check combines. **What was
missing was not the commitments. It was opening one combination per party
instead of one over all inputs.**

| | statement | outcome |
|---|---|---|
| today | `s = sum_j c_j v_j + m` against `sum_j c_j C_j + C_m` | *an* input was substituted |
| **per party** | `s_p = sum_j c_j x_{p,j} + m_p` against `sum_j c_j C_{p,j} + C_{m_p}` | **node `p` did it** |

`sum_p s_p` is the old opening with the old mask, so this is strictly stronger
rather than an alternative. The soundness argument is unchanged and now applies
per party: the coefficients come from the commitments, so a node has to choose
its error before it can see the coefficient that would cancel it.

**Built and measured** --- `zk/input_check.py` `build_per_party` /
`verify_per_party`, 26 tests, `host-a`:

| inputs | verify, aggregate | verify, per party | |
|---:|---:|---:|---:|
| 16 | 1.52 ms | 10.61 ms | 6.98x |
| 64 | 5.74 ms | 40.00 ms | 6.97x |
| **166** | **14.01 ms** | **103.54 ms** | **7.39x** |

and it named the substituting node at every size.

**Two things came out that were not obvious.**

**It needs a *narrower* field: 160 bits against the aggregate check's 164.**
Party `p` combines *shares*, which are `value_bits + SLACK_BITS = 71` wide
rather than 31, so its combination is wider --- but the mask is that party's own
input and is **not dealt across nodes**, so it does not pay the share slack plus
`log2(n)` that forced the aggregate check to 164. The term that dominated
`BINDING.md` section 3.1 simply is not there.

**And there is no capacity limit.** The Reed--Solomon decode caps at `T = 2` and
refuses at three. This names *any* number of substituting nodes, tested to all
seven, because each party's check stands alone against that party's own
commitments. **That matters, because the case a decoder gives up on is exactly
the case an operator most needs a name for.**

### And the circuit now emits it

`gen_qomm --check-mode per-party`. `secret_input()` folds each share into its
own node's accumulator **as it is read**, because once the sum is formed the
shares are gone; the coefficient is a compile-time constant, so the combination
is local and only the openings travel. The masks are the one input here that is
not split: one is read from each node, which is what makes the field
requirement smaller.

Measured end to end on `host-a`, `M = 16`, seven parties, `T = 2`, 192-bit
field, every arm verified against the cleartext reference:

| | rounds | global | openings | what a failure says |
|---|---:|---:|---:|---|
| no check | 70 | 41.5443 MB | 0 | --- |
| aggregate | 71 | 41.5521 MB | 7 | *an* input was substituted |
| **per party** | **71** | **41.5804 MB** | **49** | **node `p` substituted its input** |

**Naming costs zero extra rounds and 0.068% more traffic than merely
detecting.** Against no check at all it is one round and 0.087%.

Forty-nine openings rather than seven because at the 6-bit coefficients the
generator emits, one combination binds a party at about `2^-6`, so seven
repetitions give `2^-42` --- *per party*. They are independent, so they cost one
round together, which is why the round count does not move.

*The prediction said 3 kB and it was 28.3 kB.* The estimate assumed seven
openings and forgot that soundness per party has to be bought by repetition the
same way the aggregate check buys it. The conclusion --- negligible --- survives;
the number was ten times light.

**So the answer splits, and both halves now have a mechanism.** Who sent a
malformed share: named by the engine, patch applied, 1.33x. Who lied about their
input: named by the dealer's own commitments, built and measured at 7.4x the
check and a narrower field, with the circuit emission left to do.

### Why a griefing abort is worse here than in generic MPC

In most MPC deployments an abort is a liveness problem: retry. **In an auction it
is an economic instrument.** A node that can abort at will, anonymously and at no
cost, can suppress the quotes it does not like --- and a node colluding with a
maker can suppress exactly the ones where that maker is about to be picked off.
That converts a denial of service into a free option.

**This is the application-level reason accountability matters here more than the
generic intuition suggests**, and it is why rung 1 is a worse place to be sitting
than "the protocol occasionally fails" makes it sound.

---

## 4. Accountability is a different question and does not have a free answer

Not stopping and naming the party that tried to stop you are separate
properties, and the second one is not delivered by the first.

**GSZ identifies, but towards the wrong audience.** Its dispute control names
either a corrupted party or a *disputed pair* --- the mechanism is that the king
accuses, the relay states its opinion, and the parties broadcast the value under
dispute --- and the circuit is cut into segments so a failure discards one
segment rather than the run. That is why the worst case is 7.5 rather than 5.5.
**But it is identification towards the other parties.** An outside auditor
reading the transcript is not the party being convinced, and rung 4 needs a
judge.

**Rivinius et al. do deliver rung 4 and 5 together, and their number is the one
to respect**: publicly verifiable *plus* accountable *plus* robust costs **11x to
20x the online phase** against plain SPDZ, at `n = 3`, `t = 2`. That is in a
dishonest-majority SPDZ-like protocol with lattice commitments on every share,
which is a much harder starting point than an honest majority --- but it is the
only measured price for the full package in the literature, and nothing here
should imply it is cheap.

**Wang et al. (2025) get complete identifiability plus robustness in the
dishonest majority setting** --- and buy the robustness with a **semi-honest
trusted third party**. That is the same weakening Prime Match makes with its
bank, and it is not available to a venue whose premise is that no party can be
trusted with the order flow.

### What accountability would take here, in order of difficulty

**Rung 4 at the dealing boundary is already there** and costs nothing more.

**Rung 4 inside the MPC is the hard one, and it is the same gap as
`BINDING.md`.** A judge can only convict on what is on the bulletin board. Today
the bulletin board carries the dealt shares and their signatures; it does not
carry what each node fed the engine. Closing that is what section 3 of
`BINDING.md` prices at one extra round --- and the input check gives *detection*,
not a verdict: it says the combination does not match, not which node broke it.
**Turning detection into a verdict means one check per node rather than one for
all of them**, which is `n` times the openings, and nothing in this repository
has measured that.

**Rung 5 is available and unimplemented**, at negative cost, per section 3.

---

## 4.5 The prediction, and the way it split

Written into `artifacts/robustness_prediction.json` and committed before the
runner had been run once:

| predicted | measured | |
|---|---|---|
| MP-SPDZ malicious Shamir spends 2 to 8 elements per party, most likely about 4 | **8.000 online**, **48.231 single-phase** | see below |
| GSZ over that baseline: 0.7x to 2.8x, most likely 1.4x | **0.69x against online**, **0.11x against the total** | see below |
| rounds flat in the batch size | flat at 3 (after the loop was fixed) | landed |

**Both rows landed against the online figure and missed against the total, and
the prediction did not say which one it meant.** Eight is the top of the
predicted range; 0.69 is one hundredth below its floor. Against the single-phase
number the same prediction is out by six times and by a factor of six the other
way.

So this is not a modelling error. **It is a prediction that named a quantity
without naming its phase** --- and the phase is the thing that has now bitten
this project three times: once with edaBits, where preprocessing measured in a
single-phase harness came out two orders of magnitude wrong; once with the
`-P`/`-F` compile flag; and now here, where the arithmetic was right and the
sentence was ambiguous.

**The conclusion is stronger than the prediction either way.** Robustness was
predicted to cost about 1.4x. It saves between 1.4x and 6.4x depending on which
phase it is compared against, and on both readings it is not a cost.

---

## 4.6 What if there were no honest majority at all?

The rungs above take the corruption model as given. The other move is to change
it: drop the assumption that five of seven nodes are honest and use a protocol
that survives `n-1` corruptions instead. That is **strictly stronger** --- at
`n = 7` it withstands six colluding nodes where this design breaks at three ---
so the only question is the price.

Measured with the same slope harness, `host-a`, 128-bit field
(`artifacts/dishonest_majority.json`). The harness cross-checks: 48.235 elements
per party at the quote circuit's 3,312 multiplications predicts **17.9 MB**
global, against **19.37 MB** measured end to end in `matched_field.json`, the
difference being the input sharing and the 70 openings.

| | elements per party per multiplication |
|---|---:|
| Shamir malicious, `n=7 T=2`, **online only** | 8.000 |
| **MASCOT, `n=7`, online only** | **3.429** |
| Shamir malicious, `n=7 T=2`, **total** | 48.235 |
| semi-honest dishonest majority, `n=7`, total | 3,849 |
| **MASCOT, `n=7`, total** | **26,894** |
| MASCOT, `n=3`, total | 8,969 |
| MASCOT, `n=2`, total | 4,487 |

**The answer splits in two and the halves point opposite ways.**

**Online, dishonest majority is 2.3x cheaper.** MASCOT spends 3.429 elements per
party against Shamir's 8.000. The reason is structural rather than incidental:
reconstructing a Shamir sharing collects `2t+1 = 5` shares, while opening an
additive sharing is one round trip through a designated party whatever `n` is.
**The honest majority's entire advantage is in preprocessing, and at seven
parties its online phase is the worse of the two.**

**In total, dishonest majority is 558x more expensive**, because triples stop
coming from information-theoretic tricks and start needing pairwise oblivious
transfer. The scaling is exactly linear in the number of partners --- `4,486.6 x
(n-1)` per party, which reproduces at `n = 2, 3, 7` to three digits --- so the
global cost is quadratic in `n`, which is why nobody runs seven.

**And giving up malicious security does not recover it.** Semi-honest dishonest
majority is still 3,849 elements per party, 80x honest-majority Shamir. **The
cost is the corruption model, not the adversary model.**

### The number a deployment would actually care about

Preprocessing is input-independent, so an RFQ venue can make triples between
quotes. That turns the comparison from latency into a throughput ceiling. Per
quote at `M = 16` (3,312 multiplications), fully pipelined, with a dedicated
gigabit link per party:

| | per party, per quote | ceiling |
|---|---:|---:|
| Shamir `n=7`, total | 2.56 MB | **one quote per 0.02 s** |
| MASCOT `n=2`, total | 238 MB | one quote per 1.9 s |
| MASCOT `n=7`, total | 1.43 GB | one quote per 11.4 s |

**This design is nowhere near its bandwidth ceiling**, which is why
`DEPLOYMENT.md` finds it limited by round trips --- 3.6 s at 15 ms and 23.0 s
intercontinental. A dishonest-majority venue would be limited by bandwidth
instead, and at seven parties by a wide margin.

### The two things this actually costs, which are not bandwidth

**Robustness stops being expensive and becomes impossible.** One corrupt party
of `n` can always stall, so guaranteed output delivery is unavailable at any
price. Everything in section 3 --- the finding that robustness here is a saving
--- would be closed off permanently.

**And nobody would deploy seven.** The point of a dishonest-majority protocol is
that one honest party of two suffices, so the honest comparison is not
seven-party Shamir against seven-party MASCOT; it is **seven-party Shamir against
two-party MASCOT**, which is roughly Prime Match's shape. That is a governance
decision rather than a performance one: seven KYB'd entities across
jurisdictions is a consortium, two operators is a venue, and DeFMI's regional
node structure is built on the first.

Even so, two-party MASCOT moves **475 MB of global traffic per quote against
17.9 MB** --- 27x, with two nodes instead of seven.

### The prediction, and how it split

| predicted | measured | |
|---|---|---|
| MASCOT online at `n=7`: 12 to 20 elements per party | **3.429** | **wrong, and in the opposite direction** |
| MASCOT total at `n=7`: 30x to 300x, likely 100x | **558x** | wrong, 1.9x above the range |
| semi-honest dishonest majority still well above Shamir | 80x | landed |

**The online miss is the instructive one.** The arithmetic said "an opening
means every party sends to every other, so `2(n-1) = 12` elements". That is what
*Shamir* does here, not what SPDZ does --- SPDZ opens through a designated party
and pays `O(1)` per party regardless of `n`. **The mistake was assuming the
protocol we run is the efficient one on the axis being compared.** It is the
same shape as the earlier finding that MP-SPDZ's malicious Shamir is 6x off the
state of the art for its own regime.

---

## 5. What this changes about the position

`POSITION.md` says "no accountability and no robustness" and lists both as gaps
of the same kind. They are not.

**Robustness should be reclassified from a gap to an unbuilt saving.** The
setting supports it, the protocol exists, the price is below what is already
being paid, and what is missing is an implementation in the engine. That is a
statement about MP-SPDZ, not about this design.

**Accountability stays a gap, and a real one.** The only measured price for the
full package is 11x to 20x, in a harder regime, and the honest-majority version
has not been measured by anybody --- including here.

---

## 6. What is not settled

- **GSZ is not implemented here and has not been run.** The 5.5 to 7.5 figure is
  theirs, not ours. What is ours is the 8.0 and 48.2 it is being compared to.
- **The honest-majority price of rung 4 is unknown.** Rivinius et al. measured
  the dishonest-majority price; the analogous number for `t < n/3` Shamir does
  not appear to exist and is not derived here.
- **The bulletin board is assumed, not built.** Both public auditability and the
  broadcast channel that rung 5 wants at `t < n/2` need one, and this repository
  has a delay proxy on a single machine rather than seven sites with a shared
  append-only log.
- **Nothing here addresses input-party misbehaviour.** A maker that commits to a
  policy and then disputes it is a contract problem, not a protocol one, and the
  only work that treats corrupt input parties seriously is Baldimtsi et al. ---
  at the cost of exact correctness. `POSITION.md` section 3 has why that trade
  does not apply here.
