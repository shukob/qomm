"""Naming the node that sent a wrong share, from what the protocol already sends.

`ACCOUNTABILITY.md` puts this deployment on the first rung of five: an abort is
detected and nobody is named. Reading `Protocols/MaliciousShamirMC.hpp` shows
what that looks like in the engine --- reconstruct from `t+1` shares,
reconstruct again from every longer prefix, and on disagreement

    throw mac_fail("inconsistent Shamir secret sharing");

No party index appears in that string, and none is computed. **But the
information to compute one is already in the data the protocol moves**, and that
is what this module is: the decode MP-SPDZ does not do.

**Why it is there.** Shamir shares of a degree-`t` secret are evaluations of a
degree-`t` polynomial, which is a Reed--Solomon codeword `RS[n, t+1]`. At
`n = 7`, `t = 2` that is `RS[7, 3]`, minimum distance `5`, so up to
`floor((5-1)/2) = 2` errors can be corrected --- **exactly the corruption
threshold** --- and Berlekamp--Welch returns not only the corrected secret but
the *error locator polynomial*, whose roots are the evaluation points of the
parties that lied.

Three limits, stated here rather than discovered later.

**Products are weaker.** A product before degree reduction is degree `2t`, which
is `RS[7, 5]` with distance `3`, so one error is locatable and not two. The
guarantee is `T` on ordinary values and `T-1` on unreduced products, and a
protocol that wants robustness has to be designed around that rather than
decoding harder.

**It needs every share.** A public opening in MP-SPDZ collects `2t+1 = 5` of
seven. `RS[5, 3]` has distance `3` and locates one error. Locating `T` needs all
`n`, which is 40% more traffic per opening.

**And it cannot see a substituted input.** `secret_input()` sums one additive
share from each party, so a party that feeds a different number is offering a
valid sharing of a different value. Nothing is inconsistent, so there is nothing
to decode. This module answers *"who sent a malformed share"*; it does not
answer *"who lied about their value"*, which is the gap `BINDING.md` is about
and which costs `n` openings rather than one.
"""

from __future__ import annotations

from dataclasses import dataclass


def _inv(a: int, p: int) -> int:
    return pow(a % p, p - 2, p)


def evaluate(coeffs: list[int], x: int, p: int) -> int:
    """Horner, so a degree-t polynomial costs t multiplications."""
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def share(secret: int, degree: int, points: list[int], p: int, rng) -> list[int]:
    """One share per point, from a random polynomial with the secret at zero."""
    coeffs = [secret % p] + [rng.randrange(p) for _ in range(degree)]
    return [evaluate(coeffs, x, p) for x in points]


def reconstruct(points: list[int], shares: list[int], p: int) -> int:
    """Lagrange at zero. What the engine does, and it believes what it is given."""
    total = 0
    for i, xi in enumerate(points):
        num = den = 1
        for j, xj in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj)) % p
            den = (den * (xi - xj)) % p
        total = (total + shares[i] * num % p * _inv(den, p)) % p
    return total


def _solve(matrix: list[list[int]], rhs: list[int], p: int) -> list[int] | None:
    """One solution of a rectangular system over `F_p`, or `None` if there is none.

    Reduced row echelon form with free variables set to zero. A square solver
    was the first version and it was wrong: when the trial error count exceeds
    the real one the locator polynomial has a spare root, the system goes
    singular, and a solver that gives up on a zero pivot throws away a solution
    that exists.
    """
    n_cols = len(matrix[0])
    rows = [row[:] + [rhs[i]] for i, row in enumerate(matrix)]
    pivots, r = [], 0
    for col in range(n_cols):
        piv = next((i for i in range(r, len(rows)) if rows[i][col] % p), None)
        if piv is None:
            continue
        rows[r], rows[piv] = rows[piv], rows[r]
        scale = _inv(rows[r][col], p)
        rows[r] = [v * scale % p for v in rows[r]]
        for i in range(len(rows)):
            if i != r and rows[i][col] % p:
                f = rows[i][col]
                rows[i] = [(a - f * b) % p for a, b in zip(rows[i], rows[r])]
        pivots.append(col)
        r += 1
        if r == len(rows):
            break
    for i in range(r, len(rows)):
        if rows[i][n_cols] % p and not any(rows[i][c] % p for c in range(n_cols)):
            return None
    solution = [0] * n_cols
    for i, col in enumerate(pivots):
        solution[col] = rows[i][n_cols]
    return solution


@dataclass(frozen=True)
class Verdict:
    """What the decode concluded. `culprits` are indices into `points`."""

    ok: bool
    secret: int | None
    culprits: list[int]
    reason: str

    @property
    def named(self) -> bool:
        return bool(self.culprits)


def capacity(n: int, degree: int) -> int:
    """How many wrong shares can be located, from the code parameters alone.

    `RS[n, degree+1]` has minimum distance `n - degree`, and `e` errors are
    correctable when `2e < d`. Everything this module can and cannot do follows
    from this one line, which is why it is a function and not a comment.
    """
    return max(0, (n - degree - 1) // 2)


def locate(points: list[int], shares: list[int], degree: int, p: int) -> Verdict:
    """Berlekamp--Welch: the secret, and which parties sent wrong shares.

    Solves for `Q` of degree `<= degree + e` and `E` monic of degree `e` with
    `Q(x_i) = y_i * E(x_i)` for every `i`. Then `P = Q / E` is the true
    polynomial and the roots of `E` are the liars. Trying `e` upwards means an
    honest transcript is found at `e = 0` and costs one small solve.
    """
    n = len(points)
    if n != len(shares):
        raise ValueError("one share per point")
    if n <= degree:
        raise ValueError(f"degree {degree} needs more than {degree} points")

    limit = capacity(n, degree)
    for e in range(limit + 1):
        # unknowns: Q has degree+e+1 coefficients, E has e (it is monic, so its
        # top coefficient is fixed). Q(x) - y*E(x) = 0 is linear in both.
        cols = (degree + e + 1) + e
        if cols > n:
            break
        matrix, rhs = [], []
        for x, y in zip(points, shares):
            row = [pow(x, k, p) for k in range(degree + e + 1)]
            row += [(-y * pow(x, k, p)) % p for k in range(e)]
            matrix.append(row)
            rhs.append((y * pow(x, e, p)) % p)
        solution = _solve(matrix, rhs, p)
        if solution is None:
            continue
        q = solution[:degree + e + 1]
        err = solution[degree + e + 1:] + [1]        # monic
        poly, exact = _divide(q, err, p)
        if not exact:
            continue
        while len(poly) > 1 and poly[-1] % p == 0:
            poly.pop()
        if len(poly) - 1 > degree:
            continue
        # name the culprits from the recovered polynomial rather than from the
        # roots of E. When `e` overshoots, E has spare roots that belong to
        # nobody, and a share that actually agrees with the polynomial is not
        # evidence against its sender.
        culprits = [i for i, (x, y) in enumerate(zip(points, shares))
                    if evaluate(poly, x, p) != y % p]
        if len(culprits) > limit:
            continue
        return Verdict(True, evaluate(poly, 0, p), culprits,
                       "consistent" if not culprits else
                       f"{len(culprits)} share(s) do not lie on the polynomial")
    return Verdict(False, None, [],
                   f"more than {limit} wrong shares: at n={n} and degree {degree} "
                   f"the code has distance {n - degree}, so this is beyond what "
                   f"any decoder can resolve")


def _divide(num: list[int], den: list[int], p: int) -> tuple[list[int], bool]:
    """Polynomial division, and whether it was exact."""
    out = [0] * max(1, len(num) - len(den) + 1)
    rem = num[:]
    scale = _inv(den[-1], p)
    for i in range(len(rem) - len(den), -1, -1):
        c = rem[i + len(den) - 1] * scale % p
        out[i] = c
        for j, d in enumerate(den):
            rem[i + j] = (rem[i + j] - c * d) % p
    return out, not any(v % p for v in rem)
