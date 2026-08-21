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
