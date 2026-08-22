#!/usr/bin/env python3
"""Generate the QOMM query-oblivious quote circuit and its MP-SPDZ inputs.

The circuit implements the pricing model defined in
``papers/kyc_private_clob_defmi/private_rfq_dex_project_proposal.md``:

    q_{i,t} = P_i(x, s_{i,t}, m_t)

Market makers pre-register a secret price policy; the user secret-shares the
request. No market maker ever receives the request itself, so a losing market
maker does not learn that a request existed.

Layer structure (this is the point of the design):

    layer 1  policy arithmetic for all M market makers   -- SIMD, depth 1
    layer 2  eligibility gates for all M                 -- SIMD, depth 1
    layer 3  best-quote selection                        -- binary tree, depth log2(M)

Everything is integer arithmetic on price ticks and lots; no secret division.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from qomm_transport.roles import SLACK_BITS, check_field_width, split  # noqa: E402
import sys
from pathlib import Path

# `use_ref` is the only switch a maker cannot already throw by setting a
# coefficient to zero: `slope`, `invcoef` and `active` all admit 0, but the
# reference price used to be added with a hard-wired coefficient of one. A
# maker in a market with no usable reference sets it to 0 and carries the
# whole level in `mid` instead.
FIELDS = ("asset", "mid", "half", "slope", "invcoef", "inv", "maxqty",
          "expiry", "active", "use_ref")

def mask_bits_for(n_values: int, value_bits: int, challenge_bits: int = 40,
                  statistical_bits: int = 40) -> int:
    """How wide the input check's mask has to be to hide what it is added to.

    `zk/input_check.py` is the other half of this; the two have to agree on the
    number or the opening does not check anything. Kept here as well because the
    circuit is what has to deal the mask, and dealing it is what sets the field.
    """
    combination = value_bits + challenge_bits + max(0, (n_values - 1).bit_length())
    return combination + statistical_bits


def sentinel_for(bit_length: int, padded_mm: int, max_cost: int) -> int:
    """Sentinel that pushes ineligible market makers out of the tournament.

    The packed key is ``cost * padded_mm + index``, so the sentinel has to be
    large enough to lose against every real quote and small enough that the
    packed key still fits the signed range of the configured bit length. Getting
    this wrong produces a silently wrong winner, so the check raises instead.
    """
    headroom = 1 << (bit_length - 2)
    sentinel = headroom // padded_mm
    if sentinel <= max_cost:
        raise ValueError(
            f"bit_length={bit_length} is too narrow: packing {padded_mm} makers with costs "
            f"up to {max_cost} needs at least "
            f"{(max_cost * padded_mm * 4).bit_length() + 1} bits")
    return sentinel


def _pow2_ceil(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def build_program(
    n_mm: int,
    n_parties: int,
    mode: str,
    rfs_steps: int,
    disclose: str,
    now_t: int,
    ref_mid: int,
    band_bps: int,
    threshold_k: int,
    threshold_v: int,
    public_check: bool,
    n_requests: int = 1,
    n_assets: int = 1,
    ref_table: list | None = None,
    maker_assets: list | None = None,
    public_maker_assets: bool = False,
    audit_gates: bool = False,
    bit_length: int = 63,
    argmin_arity: int = 2,
    price_conditionals: int = 0,
    edabit: bool = False,
    trunc_pr: bool = False,
    input_check: bool = False,
    check_mode: str = "aggregate",
    check_coefficients: list | None = None,
    check_repeats: int = 7,
    stop_after: str = "tournament",
) -> str:
    """Emit the .mpc source. ``n_mm`` must be a power of two (padded by caller).

    ``stop_after`` cuts the circuit short at a named layer, so the rounds a layer
    is responsible for can be read off as the increment between two compiles
    rather than argued for. Each cut still opens something that depends on
    everything above it: a layer whose result nothing reads is a layer the
    compiler is free to delete, and a deleted layer costs nothing, which would
    make the attribution come out backwards.
    """
    if stop_after != "tournament" and mode != "rfq":
        raise ValueError(f"--stop-after names layers of the RFQ circuit; "
                         f"mode {mode} is built differently")
    ref_table = ref_table or [ref_mid]
    # a fixture stands in for the Fiat-Shamir derivation, which needs the
    # commitments; the cost does not depend on which coefficients they are.
    check_coefficients = check_coefficients or [
        1 + (617 * k) % ((1 << 6) - 1) for k in range(64)]
    maker_assets = maker_assets or [i % n_assets for i in range(n_mm)]
    lines: list[str] = []
    w = lines.append

    w('"""QOMM: query-oblivious quote evaluation (generated; do not edit).')
    w("")
    w(f"mode={mode} M={n_mm} parties={n_parties} disclose={disclose} "
      f"bits={bit_length} argmin_arity={argmin_arity} edabit={edabit} "
      f"trunc_pr={trunc_pr} "
      f"price_conditionals={price_conditionals}"
      + (f" rfs_steps={rfs_steps}" if mode == "rfs" else ""))
    w('"""')
    w("")
    w(f"program.set_bit_length({bit_length})")
    if edabit:
        w("# push comparison bit generation into preprocessing")
        w("program.use_edabit(True)")
    if trunc_pr:
        w("# probabilistic truncation: the mask is value-width plus a statistical")
        w("# gap rather than a whole field element, which is the difference that")
        w("# a wide field makes to a comparison.")
        w("program.use_trunc_pr = True")
    w("")
    w(f"M = {n_mm}")
    w(f"N_PARTIES = {n_parties}")
    w(f"LARGE = {sentinel_for(bit_length, n_mm, 8 * max(ref_table))}")
    w(f"NOW_T = {now_t}")
    w(f"N_ASSETS = {n_assets}")
    w("# Public reference price per asset. The table is public; which entry the")
    w("# request selects is not, so the selection has to be oblivious.")
    w(f"REF_TABLE = {ref_table}")
    w(f"MAKER_ASSET = {maker_assets}")
    w(f"REF_MID = {ref_mid}   # only used for the sentinel scale")
    w("")
    if check_mode == "per-party":
        w(f"CHECK_COEFF = {check_coefficients}")
        w("")
    w("# ---- how a secret gets in ----")
    w("# An input party is not a computing party. The trader and each market")
    w("# maker split their values into N shares that sum to them over the")
    w("# integers and hand share p to node p; the program adds the N inputs")
    w("# back. Reconstruction is local, so this costs rounds only in the input")
    w("# phase, and no computing node ever holds a whole request or policy.")
    if check_mode == "per-party":
        # One accumulator per node, folded at read time. After secret_input()
        # forms the sum the shares are gone, so the combination has to be built
        # as they arrive. The coefficient is a compile-time constant, so public
        # times secret stays local and only the opening below travels.
        w(f"CHECK_REPEATS = {check_repeats}")
        w("check_acc = [[sint(0) for _ in range(N_PARTIES)]")
        w("             for _ in range(CHECK_REPEATS)]")
        w("check_pos = [0]")
        w("")
        w("def secret_input():")
        w("    total = None")
        w("    _k = check_pos[0]")
        w("    _shares = [sint.get_input_from(_p) for _p in range(N_PARTIES)]")
        w("    for _r in range(CHECK_REPEATS):")
        w("        _c = CHECK_COEFF[(_r * 7919 + _k) % len(CHECK_COEFF)]")
        w("        for _p in range(N_PARTIES):")
        w("            check_acc[_r][_p] = check_acc[_r][_p] + _shares[_p] * _c")
        w("    for _s in _shares:")
        w("        total = _s if total is None else total + _s")
        w("    check_pos[0] += 1")
        w("    return total")
    else:
        w("def secret_input():")
        w("    total = sint.get_input_from(0)")
        w("    for _p in range(1, N_PARTIES):")
        w("        total = total + sint.get_input_from(_p)")
        w("    return total")
    w("")
    w("# ---- user request, shared by the trader across every node ----")
    w(f"N_REQ = {n_requests}")
    w("req_asset = Array(N_REQ, sint)")
    w("req_qty = Array(N_REQ, sint)")
    w("req_dir = Array(N_REQ, sint)   # 0 = user buys (takes ask), 1 = user sells")
    w("req_entity = Array(N_REQ, sint)")
    w("for r in range(N_REQ):")
    w("    req_asset[r] = secret_input()")
    w("    req_qty[r] = secret_input()")
    w("    req_dir[r] = secret_input()")
    w("    req_entity[r] = secret_input()")
    w("u_asset = req_asset[0]")
    w("u_qty = req_qty[0]")
    w("u_dir = req_dir[0]")
    w("u_entity = req_entity[0]")
    w("# Every slot runs on the fixed schedule whether or not a real request")
    w("# arrived. The flag is secret and never branched on, so the circuit shape,")
    w("# the round count and the byte count are identical either way; it only")
    w("# stops a dummy slot from moving market-maker state.")
    w("u_is_real = secret_input()")
    w("")
    w("# The trader's one-time mask. The answer leaves the circuit as")
    w("# `best_key + mask` opened to everyone, which is uniform to everyone but")
    w("# the trader, who subtracts. `reveal_to(0)` handed the winning price and")
    w("# the winning maker to computing node 0 in the clear -- the one party")
    w("# that is not supposed to learn the answer to a request it cannot read.")
    w("u_mask = secret_input()")
    w("")
    w("# ---- market-maker price policies, one column per field ----")
    for f in FIELDS:
        w(f"col_{f} = Array(M, sint)")
    w("")
    w("# Each maker deals its own policy to every node. The previous form gave")
    w("# maker i entirely to node i % N_PARTIES, which is a policy in the clear")
    w("# at one of the nodes it is supposed to be hidden from.")
    w("for i in range(M):")
    for f in FIELDS:
        w(f"    col_{f}[i] = secret_input()")
    w("")
    if check_mode == "per-party":
        w("")
        w("# ---- input check, one opening per node ----------------------------")
        w("# The aggregate form below proves that AN input was substituted. This")
        w("# one proves WHICH NODE did it, which is the difference between the")
        w("# first and the fourth of the five rungs in ACCOUNTABILITY.md.")
        w("#")
        w("# Each node's accumulator was folded as its shares were read, because")
        w("# after secret_input() forms the sum the shares are gone. The masks")
        w("# are the one place the shape differs from every other input here:")
        w("# each is read from a single node rather than split across all of")
        w("# them, which is why the check needs 160 bits of field where the")
        w("# aggregate one needs 164.")
        w("#")
        w("# `zk/input_check.py` build_per_party / verify_per_party is the other")
        w("# half. It combines the same coefficients into the share commitments")
        w("# `roles.Dealing` already publishes, so a failing opening names a node")
        w("# from data anybody has.")
        w("for _r in range(CHECK_REPEATS):")
        w("    for _p in range(N_PARTIES):")
        w("        _combined = check_acc[_r][_p] + sint.get_input_from(_p)")
        w("        print_ln('QOMM_PER_PARTY_CHECK_%s_%s=%s', _r, _p,")
        w("                 _combined.reveal())")
        w("")
    elif input_check:
        w("")
        w("# ---- input check: one random linear combination -------------------")
        w("# The coefficients are public and derived from the commitments the")
        w("# dealer published, so a node choosing what to substitute cannot see")
        w("# them first. Public times secret is local, so the combination costs")
        w("# no communication at all; the opening below is the whole price.")
        w("# `zk/input_check.py` is the other half --- it combines the same")
        w("# coefficients into the commitments and checks this opening against it.")
        w("# Repetition rather than wider coefficients: at 127 bits the budget is")
        w("# challenge + hiding <= 41, so soundness is bought back by opening")
        w("# several independent combinations, which cost one round together")
        w("# because none of them waits on another.")
        w(f"CHECK_COEFF = {check_coefficients}")
        w(f"CHECK_REPEATS = {check_repeats}")
        w("check_masks = [secret_input() for _ in range(CHECK_REPEATS)]")
        w("for _r in range(CHECK_REPEATS):")
        w("    combination = check_masks[_r]")
        w("    _k = 0")
        w("    for i in range(M):")
        for f in FIELDS:
            w(f"        combination = combination + col_{f}[i] * "
              f"CHECK_COEFF[(_r * 7919 + _k) % len(CHECK_COEFF)]")
            w("        _k += 1")
        w("    print_ln('QOMM_INPUT_CHECK_%s=%s', _r, combination.reveal())")
        w("")
    w("idx = Array(M, sint)")
    w("for i in range(M):")
    w("    idx[i] = sint(i)")
    w("wide_idx = Array(M * N_REQ, sint)")
    w("for r in range(N_REQ):")
    w("    for i in range(M):")
    w("        wide_idx[r * M + i] = sint(i)")
    w("")
    w("")
    w("# ---- oblivious reference-price lookup ----")
    w("# ref = sum_a (asset == a) * REF_TABLE[a]. Each term multiplies a secret")
    w("# bit by a public constant, which costs nothing, so the whole lookup is")
    w("# N_ASSETS equality tests in one layer. Selecting the row publicly would")
    w("# announce which market the request is for, which is the thing to avoid.")
    w("ref_secret_per_request = Array(N_REQ, sint)")
    w("asset_onehot = None")
    w("for r in range(N_REQ):")
    w("    onehot = [req_asset[r] == sint(a) for a in range(N_ASSETS)]")
    w("    if r == 0:")
    w("        asset_onehot = onehot")
    w("    acc = onehot[0] * REF_TABLE[0]")
    w("    for a in range(1, N_ASSETS):")
    w("        acc = acc + onehot[a] * REF_TABLE[a]")
    w("    ref_secret_per_request[r] = acc")
    w("ref_secret = ref_secret_per_request[0]")
    w("")
    if public_maker_assets:
        w("# gather the one-hot bit for each maker's publicly known market")
        w("asset_gate = Array(M, sint)")
        w("for i in range(M):")
        w("    asset_gate[i] = asset_onehot[MAKER_ASSET[i]]")
        w("")
    w("# One job serves N_REQ requests. Every per-maker vector is widened to")
    w("# N_REQ*M so the comparison layers are shared: rounds are a property of the")
    w("# job, not of the request, which is what makes batching worth doing.")
    w("WIDE = N_REQ * M")
    w("def tile_makers(vec):")
    w("    out = Array(WIDE, sint)")
    w("    for r in range(N_REQ):")
    w("        out.assign(vec, r * M)")
    w("    return out.get_vector()")
    w("def spread_request(arr):")
    w("    out = Array(WIDE, sint)")
    w("    for r in range(N_REQ):")
    w("        out.assign(arr[r].expand_to_vector(M), r * M)")
    w("    return out.get_vector()")
    w("qty_v = spread_request(req_qty)")
    w("asset_v = spread_request(req_asset)")
    w("dir_v = spread_request(req_dir)")
    w("")
    w("inv_state = Array(M, sint)")
    w("inv_state.assign(col_inv.get_vector())")
    w("")
    w("")
    w("def pack_key(cost, index_vec):")
    w('    """Pack the tie-breaking index into the low bits.')
    w("")
    w("    Two things fall out of this. Keys become unique, so a strict comparison")
    w("    is enough and no tie-breaking logic is needed. And the winning index")
    w("    travels inside the value, so the tournament no longer has to carry a")
    w("    second secret array and pay a second multiplication at every level.")
    w('    """')
    w("    return cost * M + index_vec")
    w("")
    w("")
    w("# The packed key is only ever unpacked after it is opened, by whoever")
    w("# received it. Doing it in secret would cost a division and a modulo.")
    w("")
    w("")
    w("def min_tree(keys, n):")
    w('    """Binary tournament: depth log2(n), one comparison and one select per level."""')
    w("    cur = Array(n, sint)")
    w("    cur.assign(keys)")
    w("    size = n")
    w("    while size > 1:")
    w("        half = size // 2")
    w("        a = cur.get_vector(0, half)")
    w("        b = cur.get_vector(half, half)")
    w("        cur.assign((a < b).if_else(a, b), 0)")
    w("        size = half")
    w("    return cur[0]")
    w("")
    w("")
    w("def min_kary(keys, n, arity):")
    w('    """Arity-k tournament: depth log_k(n) levels, k(k-1) comparisons per group.')
    w("")
    w("    Trades comparison count for circuit depth. Depth costs round trips, which")
    w("    are the binding constraint over a wide area; comparison count costs")
    w("    bandwidth, which is not. The best arity therefore depends on the link, so")
    w("    it is left as a measured parameter rather than a fixed choice.")
    w('    """')
    w("    cur = Array(n, sint)")
    w("    cur.assign(keys)")
    w("    size = n")
    w("    while size > 1:")
    w("        a = min(arity, size)")
    w("        groups = size // a")
    w("        # block p holds the p-th member of every group, so each block is contiguous")
    w("        blocks = [cur.get_vector(p * groups, groups) for p in range(a)]")
    w("        ranks = []")
    w("        for p in range(a):")
    w("            rank = None")
    w("            for q in range(a):")
    w("                if p == q:")
    w("                    continue")
    w("                less = blocks[q] < blocks[p]")
    w("                rank = less if rank is None else rank + less")
    w("            ranks.append(rank)")
    w("        # the rank is at most arity-1, so the equality does not need the")
    w("        # full key width. Comparing at full width was costing more rounds")
    w("        # than the extra tree level it was supposed to remove.")
    w("        rank_bits = max(2, (a - 1).bit_length() + 1)")
    w("        winner = None")
    w("        for p in range(a):")
    w("            selected = ranks[p].equal(0, rank_bits)")
    w("            term = selected * blocks[p]")
    w("            winner = term if winner is None else winner + term")
    w("        cur.assign(winner, 0)")
    w("        size = groups")
    w("    return cur[0]")
    w("")
    w("")
    w("def argmin(keys, n):")
    if argmin_arity <= 2:
        w("    return min_tree(keys, n)")
    else:
        w(f"    return min_kary(keys, n, {argmin_arity})")
    w("")
    w("")
    w("def quote_layer(inv_vec, ref_secret, now_t):")
    w('    """One evaluation of P_i(x, s_i, m_t) for every market maker at once."""')
    w("    mid = tile_makers(col_mid.get_vector())")
    w("    half = tile_makers(col_half.get_vector())")
    w("    slope = tile_makers(col_slope.get_vector())")
    w("    invcoef = tile_makers(col_invcoef.get_vector())")
    w("    maxqty = tile_makers(col_maxqty.get_vector())")
    w("    expiry = tile_makers(col_expiry.get_vector())")
    w("    active = tile_makers(col_active.get_vector())")
    w("    asset_mm = tile_makers(col_asset.get_vector())")
    w("    # layer 1: price policy (2 SIMD multiplications, depth 1)")
    w("    skew = invcoef * tile_makers(inv_vec)")
    w("    depth = slope * qty_v")
    w("    # mid is the maker's offset from the reference for its own asset,")
    w("    # unless the maker switched the reference off, in which case mid is")
    w("    # the level itself. One more multiplication in a layer that already")
    w("    # has two, so the depth --- and the round count --- does not move.")
    w("    use_ref = tile_makers(col_use_ref.get_vector())")
    w("    anchored = mid + use_ref * spread_request(ref_secret_per_request)")
    if price_conditionals:
        w(f"    # {price_conditionals} conditional(s) on secrets in the price rule.")
        w("    # A branch on a secret is a comparison, and comparisons are what")
        w("    # rounds are made of --- but every maker is evaluated at once, so")
        w("    # this costs its depth once rather than once per maker.")
        for index in range(price_conditionals):
            bound = 200 * (index + 1)
            if index % 2 == 0:
                w(f"    skew = (skew > sint({-bound})).if_else(skew, sint({-bound}))")
            else:
                w(f"    skew = (skew < sint({bound})).if_else(skew, sint({bound}))")
    w("    ask = anchored + half + depth + skew")
    w("    bid = anchored - half - depth + skew")
    if stop_after in ("price", "direction"):
        w("    # Cut before the eligibility layer. Nothing below this line is built,")
        w("    # so the rounds this circuit costs are the price layer's own.")
        w("    return ask, bid, None, maxqty")
    else:
        w("    # layer 2: eligibility (3 SIMD comparisons + 3 SIMD multiplications, depth 1+cmp)")
        if public_maker_assets:
            w("    # The market each maker serves is public business information; only the")
            w("    # *user's* asset is secret. So the asset gate is a public index into the")
            w("    # secret one-hot vector, which costs no communication at all, instead of")
            w("    # an equality test per maker.")
            w("    g_asset = tile_makers(asset_gate.get_vector())")
        else:
            w("    g_asset = asset_mm == asset_v")
        w("    g_qty = qty_v <= maxqty")
        if audit_gates:
            w("    # expiry and the active flag are proved at registration time by the")
            w("    # policy audit, so re-checking them here would pay for the same fact twice")
            w("    ok = g_asset * g_qty")
        else:
            w("    g_exp = expiry > sint(now_t)")
            w("    ok = active * g_asset * g_qty * g_exp")
        w("    return ask, bid, ok, maxqty")
    w("")
    w("")

    if disclose == "threshold":
        w(f"BAND = {band_bps} * REF_MID // 10000")
        w(f"THRESHOLD_K = {threshold_k}")
        w(f"THRESHOLD_V = {threshold_v}")
        w("")
        w("")
        w("def threshold_disclosure(ask, ok, maxqty, ref_secret):")
        w('    """ZK-style threshold statement: >=K independent MMs, >=V size, inside the band."""')
        w("    lo = ask >= (ref_secret - BAND).expand_to_vector(M)")
        w("    hi = ask <= (ref_secret + BAND).expand_to_vector(M)")
        w("    in_band = lo * hi")
        w("    elig = ok * in_band")
        w("    size_v = elig * maxqty")
        w("    elig_a = Array(M, sint)")
        w("    elig_a.assign(elig)")
        w("    size_a = Array(M, sint)")
        w("    size_a.assign(size_v)")
        w("    n_ok = elig_a[0]")
        w("    vol = size_a[0]")
        w("    for i in range(1, M):")
        w("        n_ok = n_ok + elig_a[i]")
        w("        vol = vol + size_a[i]")
        w("    return (n_ok >= sint(THRESHOLD_K)) * (vol >= sint(THRESHOLD_V))")
        w("")
        w("")

    if mode == "rfq":
        w("ask, bid, ok, maxqty = quote_layer(inv_state.get_vector(), ref_secret, NOW_T)")
        # Each cut opens one value that every layer above it feeds, so nothing
        # already built can be optimised away and the increment between two cuts
        # is the layer between them.
        if stop_after == "price":
            w("# stage cut: open one value that both priced sides feed")
            w("stage_out = Array(WIDE, sint)")
            w("stage_out.assign(ask + bid)")
            w("stage_out.get_vector().reveal_to(0)")
            return "\n".join(lines) + "\n"
        w("# direction stays secret: minimise the user's cost on whichever side applies")
        w("cost = dir_v.if_else(-bid, ask)")
        if stop_after == "direction":
            w("# stage cut: the selection is built, the gates are not")
            w("stage_out = Array(WIDE, sint)")
            w("stage_out.assign(cost)")
            w("stage_out.get_vector().reveal_to(0)")
            return "\n".join(lines) + "\n"
        w("cost = ok.if_else(cost, sint(LARGE))")
        if stop_after == "gates":
            w("# stage cut: everything but the tournament")
            w("stage_out = Array(WIDE, sint)")
            w("stage_out.assign(cost)")
            w("stage_out.get_vector().reveal_to(0)")
            return "\n".join(lines) + "\n"
        w("wide_keys = Array(WIDE, sint)")
        w("wide_keys.assign(pack_key(cost, wide_idx.get_vector()))")
        w("best_key = argmin(wide_keys.get_vector(0, M), M)")
        w("for r in range(1, N_REQ):")
        w("    (argmin(wide_keys.get_vector(r * M, M), M) + u_mask).reveal()")
        w("# one opened value carries both the winning price and the winning")
        w("# maker, under the trader's mask")
        w("print_ln('QOMM_MASKED_KEY=%s', (best_key + u_mask).reveal())")
        w("")
        w("# Each node keeps its *share* of the answer, written where the joint")
        w("# prover reads it. This is the binding the design has been missing:")
        w("# the quote proof is assembled from shares, and until now those")
        w("# shares were supplied to the prover separately from the ones the")
        w("# circuit computed on, so nothing said they were the same numbers.")
        w("# Writing them here and reading them there makes it one value")
        w("# crossing a named interface rather than two that agree.")
        w("sint.write_to_file([best_key])")

        if disclose == "threshold":
            w("pub = threshold_disclosure(ask, ok, maxqty, ref_secret)")
            w("print_ln('QOMM_DISCLOSE=%s', pub.reveal())")

    elif mode == "rfm":
        w("ask, bid, ok, maxqty = quote_layer(inv_state.get_vector(), ref_secret, NOW_T)")
        w("# two-sided: the direction is never supplied at all")
        w("ask_cost = ok.if_else(ask, sint(LARGE))")
        w("bid_cost = ok.if_else(-bid, sint(LARGE))")
        w("ask_key = argmin(pack_key(ask_cost, idx.get_vector()), M)")
        w("bid_key = argmin(pack_key(bid_cost, idx.get_vector()), M)")
        w("print_ln('QOMM_MASKED_ASK=%s', (ask_key + u_mask).reveal())")
        w("print_ln('QOMM_MASKED_BID=%s', (bid_key + u_mask).reveal())")
        if public_check:
            w("print_ln('QOMM_ASK_KEY=%s', ask_key.reveal())")
            w("print_ln('QOMM_BID_KEY=%s', bid_key.reveal())")
        if disclose == "threshold":
            w("pub = threshold_disclosure(ask, ok, maxqty, ref_secret)")
            w("print_ln('QOMM_DISCLOSE=%s', pub.reveal())")

    elif mode == "rfs":
        w(f"RFS_STEPS = {rfs_steps}")
        w("# Each step depends on the previous winner's inventory: a genuine serial chain.")
        w("for step in range(RFS_STEPS):")
        w("    # the reference moves with the slot, still without revealing the asset")
        w("    ask, bid, ok, maxqty = quote_layer(inv_state.get_vector(), ref_secret + step, NOW_T)")
        w("    cost = dir_v.if_else(-bid, ask)")
        w("    cost = ok.if_else(cost, sint(LARGE))")
        w("    keys = pack_key(cost, idx.get_vector())")
        w("    best_key = argmin(keys, M)")
        w("    best_key.reveal_to(0)")
        w("    # winner absorbs the flow, so the next quote sees a moved inventory.")
        w("    # Keys are unique, so matching the key identifies the winner without")
        w("    # opening the index or paying a secret division.")
        w("    won = keys == best_key.expand_to_vector(M)")
        w("    signed_qty = u_dir.if_else(qty_v, -qty_v)")
        w("    real_v = u_is_real.expand_to_vector(M)")
        w("    inv_state.assign(inv_state.get_vector() + won * signed_qty * real_v, 0)")
        if public_check:
            w("    print_ln('QOMM_RFS_STEP_%s_KEY=%s', step, best_key.reveal())")
        if disclose == "threshold":
            w("pub = threshold_disclosure(ask, ok, maxqty, ref_secret)")
            w("print_ln('QOMM_DISCLOSE=%s', pub.reveal())")
    else:
        raise ValueError(f"unknown mode {mode}")

    return "\n".join(lines) + "\n"


def build_inputs(
    n_mm: int,
    n_real_mm: int,
    n_parties: int,
    is_real: int,
    n_requests: int,
    n_assets: int,
    ref_table: list,
    user_asset: int,
    user_qty: int,
    user_dir: int,
    user_entity: int,
    now_t: int,
    ref_mid: int,
    seed: int,
    audit_gates: bool = False,
    value_bits: int = 32,
    field_bits: int = 128,
    use_ref: int = 1,
    input_check: bool = False,
    check_mode: str = "aggregate",
    check_coefficients: list | None = None,
    check_repeats: int = 7,
) -> tuple[dict[int, list[int]], dict]:
    """Deterministic policy fixture. Padding slots are inactive.

    Returns (per-party input list, cleartext reference used to check the result).
    """
    rng = random.Random(seed)
    per_party: dict[int, list[int]] = {p: [] for p in range(n_parties)}

    # An input party splits its value and hands one share to each node, in the
    # order `secret_input()` reads them. Party p's file therefore holds one
    # share of every secret and no whole value of anything -- which
    # `tests/test_mpc_inputs.py` checks rather than trusts.
    check_field_width(n_parties, value_bits, field_bits)

    # The sharing draws from its own stream. Sharing off `rng` would make the
    # policy fixture depend on how many values had been split before it, so the
    # same seed would stop meaning the same market.
    share_rng = random.Random(seed ^ 0x5EED)

    def deal(value: int, width: int | None = None) -> None:
        for party, share in enumerate(split(int(value), n_parties,
                                            value_bits if width is None else width,
                                            share_rng)):
            per_party[party].append(share)

    for _ in range(n_requests):
        for value in (user_asset, user_qty, user_dir, user_entity):
            deal(value)
    deal(int(is_real))
    # The trader's mask. Drawn here because the fixture stands in for the
    # trader; a deployment draws it on the trader's own machine and keeps it.
    mask = share_rng.randrange(1 << value_bits)
    deal(mask)

    policies = []
    for i in range(n_mm):
        if i < n_real_mm:
            # makers are spread across every asset, so the requested market is
            # one of several the same circuit serves
            asset = i % n_assets
            pol = {
                "asset": asset,
                "mid": rng.randint(-15, 15),   # offset from the asset's reference
                "half": rng.randint(5, 40),
                "slope": rng.randint(0, 3),
                "invcoef": rng.randint(0, 2),
                "inv": rng.randint(-50, 50),
                "maxqty": rng.choice([50, 100, 200, 500]),
                "expiry": now_t + rng.randint(1, 600),
                "active": 1,
                "use_ref": (use_ref[i % len(use_ref)]
                            if isinstance(use_ref, (list, tuple))
                            else use_ref),
            }
        else:  # padding to the next power of two
            pol = {
                "asset": 0, "mid": 0, "half": 0, "slope": 0, "invcoef": 0,
                "inv": 0, "maxqty": 0, "expiry": 0, "active": 0, "use_ref": 0,
            }
        policies.append(pol)
        for f in FIELDS:
            deal(pol[f])

    if input_check:
        # The mask the combination is opened under, read last because the circuit
        # reads it last. Without it the opening is one linear equation in the
        # policy, and enough of them solve for it.
        #
        # It is much wider than a policy field, and that width is the whole
        # reason this needs a wider prime than the default: it is dealt like
        # every other input, so the field has to hold `n_parties` shares of it.
        n_values = n_mm * len(FIELDS) + n_requests * 4 + 2
        # the width the mask has to cover is set by the coefficients the
        # circuit will actually multiply by, not by a constant
        check_bits = (max(check_coefficients).bit_length()
                      if check_coefficients else 6)
        if check_mode == "per-party":
            # One mask per node, read only from that node. This is the only
            # input here that is not split, and it is why the per-party check
            # needs 160 bits of field where the aggregate one needs 164: the
            # mask does not pay the share slack that splitting costs.
            # The mask has to hide a combination of SHARES, not of values, so
            # it is `SLACK_BITS` wider than the aggregate one at the same
            # coefficient width --- and it is read from one node rather than
            # split across them, so it does not pay that slack a second time.
            # Net at 31-bit values and 40-bit coefficients: 160 bits against
            # 164. At the wider `value_bits` a deployment actually compiles
            # with, both grow together.
            share_bits = value_bits + SLACK_BITS
            width = (share_bits + check_bits
                     + max(0, (n_values - 1).bit_length()) + 40)
            check_field_width(n_parties, value_bits, field_bits)
            if width + 1 >= field_bits:
                raise ValueError(
                    f"the per-party check needs {width + 1} bits at "
                    f"{check_bits}-bit coefficients and the field is "
                    f"{field_bits}; widen the field or narrow the coefficients")
            for _ in range(check_repeats):
                for party in range(n_parties):
                    per_party[party].append(share_rng.randrange(1 << width))
        else:
            width = mask_bits_for(n_values, value_bits, challenge_bits=6,
                                  statistical_bits=35)
            check_field_width(n_parties, width, field_bits)
            for _ in range(check_repeats):
                deal(share_rng.randrange(1 << width), width=width)

    # cleartext reference (what the circuit must reproduce)
    best_price = None
    best_mm = None
    best_ask = None
    best_bid = None
    best_ask_mm = None
    best_bid_mm = None
    quotes = []
    for i, pol in enumerate(policies):
        skew = pol["invcoef"] * pol["inv"]
        depth = pol["slope"] * user_qty
        anchor = pol.get("use_ref", 1) * ref_table[user_asset] + pol["mid"]
        ask = anchor + pol["half"] + depth + skew
        bid = anchor - pol["half"] - depth + skew
        ok = pol["asset"] == user_asset and user_qty <= pol["maxqty"]
        if not audit_gates:
            ok = ok and pol["active"] == 1 and pol["expiry"] > now_t
        quotes.append({"mm": i, "ask": ask, "bid": bid, "eligible": ok})
        if not ok:
            continue
        if best_ask is None or ask < best_ask:
            best_ask, best_ask_mm = ask, i
        if best_bid is None or bid > best_bid:
            best_bid, best_bid_mm = bid, i
        cost = -bid if user_dir == 1 else ask
        if best_price is None or cost < best_price:
            best_price, best_mm = cost, i
    reference = {
        "best_cost": best_price,
        "best_price": (-best_price if user_dir == 1 and best_price is not None else best_price),
        "best_mm": best_mm,
        "best_ask": best_ask,
        "best_bid": best_bid,
        "best_ask_mm": best_ask_mm,
        "best_bid_mm": best_bid_mm,
        "eligible_count": sum(1 for q in quotes if q["eligible"]),
        "quotes": quotes,
        # what the trader subtracts from the opened value. In a deployment this
        # never leaves the trader; here the fixture stands in for it.
        "mask": mask,
    }
    return per_party, reference


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n-mm", type=int, default=16)
    ap.add_argument("--n-parties", type=int, default=7)
    ap.add_argument("--mode", choices=("rfq", "rfm", "rfs"), default="rfq")
    ap.add_argument("--rfs-steps", type=int, default=5)
    ap.add_argument("--disclose", choices=("none", "threshold"), default="none")
    ap.add_argument("--now-t", type=int, default=1000)
    ap.add_argument("--ref-mid", type=int, default=100000)
    ap.add_argument("--n-requests", type=int, default=1,
                    help="requests served by one job; rounds are per job, so batching "
                         "is the way to lower rounds per quote")
    ap.add_argument("--public-maker-assets", action="store_true",
                    help="treat which market a maker serves as public, so the asset "
                         "gate becomes a free lookup instead of an equality test")
    ap.add_argument("--audit-gates", action="store_true",
                    help="drop expiry and the active flag from the circuit; the "
                         "registration-time policy audit already proves them")
    ap.add_argument("--n-assets", type=int, default=1,
                    help="assets the one circuit serves; the requested one stays secret")
    ap.add_argument("--band-bps", type=int, default=20)
    ap.add_argument("--threshold-k", type=int, default=5)
    ap.add_argument("--threshold-v", type=int, default=1000)
    ap.add_argument("--user-qty", type=int, default=100)
    ap.add_argument("--user-dir", type=int, default=0)
    ap.add_argument("--user-asset", type=int, default=0)
    ap.add_argument("--user-entity", type=int, default=42)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--field-bits", type=int, default=128,
                    help="width of the MPC field the shares are summed in; "
                         "must match what the program is compiled for")
    ap.add_argument("--bit-length", type=int, default=63)
    ap.add_argument("--price-conditionals", type=int, default=0,
                    help="conditionals on secrets to add to the price rule. The "
                         "language already allows these through min and max; this "
                         "is here to price them in rounds, which is the only cost "
                         "the language cannot derive on its own")
    ap.add_argument("--argmin-arity", type=int, default=2,
                    help="2 = binary tournament; larger trades comparisons for depth; "
                         "set to the padded market-maker count for a single all-pairs layer")
    ap.add_argument("--check-repeats", type=int, default=7,
                    help="independent combinations; soundness is challenge bits "
                         "times this, and they open in one round")
    ap.add_argument("--check-coefficients", type=Path, default=None,
                    help="JSON list of public coefficients. The default is a "
                         "FIXTURE and is not sound: the whole argument is that "
                         "the coefficients come after the commitments, so a "
                         "deployment derives them from the published "
                         "commitments and passes them here.")
    ap.add_argument("--check-mode", choices=("aggregate", "per-party"),
                    default="aggregate",
                    help="aggregate opens one combination and detects a "
                         "substitution; per-party opens one per node and names "
                         "the node that made it")
    ap.add_argument("--input-check", action="store_true",
                    help="emit the random linear combination that binds the "
                         "inputs to the published commitments")
    ap.add_argument("--trunc-pr", action="store_true",
                    help="probabilistic truncation for comparisons")
    ap.add_argument("--edabit", action="store_true",
                    help="generate comparison bits in preprocessing")
    ap.add_argument("--is-real", type=int, default=1, choices=(0, 1),
                    help="0 emits a cover slot: same circuit, no state change")
    ap.add_argument("--no-public-check", action="store_true")
    ap.add_argument("--stop-after", default="tournament",
                    choices=("price", "direction", "gates", "tournament"),
                    help="cut the circuit after a named layer, so the rounds that "
                         "layer costs can be read as an increment between compiles. "
                         "RFQ only: the other modes have a different shape and "
                         "attributing their cost would need its own cuts.")
    ap.add_argument("--inputs-only", action="store_true",
                    help="skip emitting the circuit; a resident service compiles "
                         "it once and only the inputs change per request")
    ap.add_argument("--out-program", type=Path, required=True)
    ap.add_argument("--out-input-dir", type=Path, required=True)
    ap.add_argument("--out-reference", type=Path, required=True)
    args = ap.parse_args()
    coefficients = (json.loads(args.check_coefficients.read_text())
                    if args.check_coefficients else None)

    padded = _pow2_ceil(args.n_mm)
    # spread the reference prices apart so a wrong asset selection is obvious
    ref_table = [args.ref_mid + 5_000 * a for a in range(args.n_assets)]
    if not 0 <= args.user_asset < args.n_assets:
        print(f"error: --user-asset must be below --n-assets", file=sys.stderr)
        return 5
    try:
        sentinel_for(args.bit_length, padded, 8 * max(ref_table))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    # A resident service compiles the circuit once and then only the inputs
    # change, so building the program text again per request is pure waste ---
    # and it is the larger half of what generation costs.
    src = "" if args.inputs_only else build_program(
        n_mm=padded,
        n_parties=args.n_parties,
        mode=args.mode,
        rfs_steps=args.rfs_steps,
        disclose=args.disclose,
        now_t=args.now_t,
        ref_mid=args.ref_mid,
        band_bps=args.band_bps,
        threshold_k=args.threshold_k,
        threshold_v=args.threshold_v,
        public_check=not args.no_public_check,
        n_requests=args.n_requests,
        n_assets=args.n_assets,
        ref_table=ref_table,
        maker_assets=[i % args.n_assets for i in range(padded)],
        public_maker_assets=args.public_maker_assets,
        audit_gates=args.audit_gates,
        bit_length=args.bit_length,
        argmin_arity=(padded if args.argmin_arity <= 0 else args.argmin_arity),
        stop_after=args.stop_after,
        price_conditionals=args.price_conditionals,
        edabit=args.edabit,
        trunc_pr=args.trunc_pr,
        input_check=args.input_check,
        check_mode=args.check_mode,
        check_coefficients=coefficients,
        check_repeats=args.check_repeats,
    )
    if not args.inputs_only:
        args.out_program.parent.mkdir(parents=True, exist_ok=True)
        args.out_program.write_text(src, encoding="utf-8")

    per_party, reference = build_inputs(
        n_mm=padded,
        n_real_mm=args.n_mm,
        n_parties=args.n_parties,
        is_real=args.is_real,
        n_requests=args.n_requests,
        n_assets=args.n_assets,
        ref_table=ref_table,
        user_asset=args.user_asset,
        user_qty=args.user_qty,
        user_dir=args.user_dir,
        user_entity=args.user_entity,
        now_t=args.now_t,
        ref_mid=args.ref_mid,
        seed=args.seed,
        audit_gates=args.audit_gates,
        # The widest value an input party splits, and the field the shares are
        # reconstructed in. Both are declared rather than assumed, because a
        # field too narrow for the shares would wrap the sum and the circuit
        # would compute on a different request than the one that was sent.
        value_bits=args.bit_length + 1,
        field_bits=args.field_bits,
        input_check=args.input_check,
        check_mode=args.check_mode,
        check_coefficients=coefficients,
        check_repeats=args.check_repeats,
    )
    args.out_input_dir.mkdir(parents=True, exist_ok=True)
    for party, values in per_party.items():
        path = args.out_input_dir / f"Input-P{party}-0"
        path.write_text(" ".join(str(v) for v in values) + "\n", encoding="utf-8")

    # the circuit opens one packed key, so the reference carries the same packing
    if reference["best_cost"] is not None:
        reference["best_key"] = reference["best_cost"] * padded + reference["best_mm"]
    if reference["best_ask"] is not None:
        reference["ask_key"] = reference["best_ask"] * padded + reference["best_ask_mm"]
        reference["bid_key"] = (-reference["best_bid"]) * padded + reference["best_bid_mm"]
    # With no eligible maker the circuit legitimately answers "no quote": every
    # key is the sentinel, so the smallest is the one at index zero. The
    # reference has to expect that rather than treat it as a mismatch.
    sentinel = sentinel_for(args.bit_length, padded, 8 * max(ref_table))
    if reference["best_cost"] is None:
        reference["no_eligible_maker"] = True
        reference["best_cost"] = sentinel
        reference["best_mm"] = 0
        reference["best_key"] = sentinel * padded
    else:
        reference["no_eligible_maker"] = False
    if reference["best_ask"] is None:
        reference["best_ask"] = sentinel
        reference["best_ask_mm"] = 0
        reference["ask_key"] = sentinel * padded
        reference["best_bid"] = -sentinel
        reference["best_bid_mm"] = 0
        reference["bid_key"] = sentinel * padded
    reference["is_real"] = args.is_real
    reference["n_assets"] = args.n_assets
    reference["ref_table"] = ref_table
    reference["user_asset"] = args.user_asset
    reference["padded_mm"] = padded
    reference["real_mm"] = args.n_mm
    reference["mode"] = args.mode
    args.out_reference.write_text(json.dumps(reference, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"padded_mm": padded, "real_mm": args.n_mm, "mode": args.mode,
                      "best_price": reference["best_price"], "best_mm": reference["best_mm"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
