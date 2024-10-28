pan-chainguard Tests
====================

``pan-chainguard`` tests use the Python
`unit testing framework
<https://docs.python.org/3/library/unittest.html>`_.

Run Tests
---------

To run all tests from the top-level directory:
::

  $ python3 -m unittest discover -v -s tests

To run a specific test from the top-level directory:
::

  $ python3 -m unittest discover -v -s tests -p test_ccadb_date.py

To run all tests from the ``tests/`` directory:
::

  $ python3 -m unittest discover -v -t ..

To run a specific test from the ``tests/`` directory:
::

  $ python3 -m unittest discover -v -t .. -p test_ccadb_date.py
