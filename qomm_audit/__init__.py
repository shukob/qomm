"""Query-oblivious auditability for the QOMM computing nodes.

Issue #129, phase 1.5: detect a computing node that omits eligible market
makers, signs two different results for one slot, reuses an old state, or stops
answering only when the answer is inconvenient -- all without revealing whether
a slot carried a real request.
"""
