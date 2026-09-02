"""Background scan execution.

A bounded thread pool with a per-scan state machine, deliberately not a
distributed queue: the workload is one job per user action. ``runner.submit``
is the only entry point, so replacing this with a real broker later means
reimplementing one function rather than unpicking the API layer.
"""
