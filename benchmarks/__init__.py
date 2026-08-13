"""Latency and throughput measurement for Hindsight against a live HydraDB node.

Nothing in this package is imported by :mod:`hindsight`, :mod:`hindsight_mcp` or
:mod:`hindsight_web`. It only reads those modules, so a benchmark can never
change the behaviour it is measuring.
"""
