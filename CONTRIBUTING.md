# Contributing

1. Fork and create a branch.
2. `pip install -e ".[dev]"` then `pytest -q`.
3. New detection rule? Add a pure function `(events, cfg) -> list[Finding]` in
   `detectors.py`, register it in `RULES`, and add tests in `tests/test_detectors.py`.
4. New log format? Add a parser in `parsers.py` that returns `Event` objects.
5. Open a pull request describing the attack pattern the change detects.
