"""Hindsight's incident console — a read-only web view over the bitemporal graph.

The package is deliberately split so that the parts worth testing do not need a
web server, and the part that needs a web server is not worth testing:

  queries    the label namespaces this console reads from. The Cypher itself is
             :mod:`hindsight.queries`, shared with the MCP server, so a human
             scrubbing the timeline and an agent asking the same question cannot
             get different answers.
  paging     the console's row cap over the client's cursor paging.
  incident   the chalk/debug incident file -> malicious version index + markers.
  analysis   timestamp/interval arithmetic and the exposure classification,
             including the wording of the "not exposed, and here is why" case.
  service    the read path: name -> id, query, shape a JSON answer.
  app        ~100 lines of Starlette routing and static file serving.

Nothing here writes. The graph is append-only and the console is a witness.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
