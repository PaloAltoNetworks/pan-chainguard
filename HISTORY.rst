Release History
===============

0.1.0 (2024-04-09)
------------------

- fling.py, chain.py, guard.py, admin-guide.rst:

  Add --debug argument and use args.debug for all debugging related
  output, and be consistent in use of args.verbose for verbose output
  (e.g., progress messages).

- chain.py:

  + Log when a CA certificate is not in any of Apple, Google Chrome,
    Microsoft, Mozilla root stores.
  + Log when 0 intermediates found for a CA certificate.

- chain.py:

  Add message when all certificate chains were downloaded
  successfully.

- chain.py:

  + Display PAN-OS certificates not in CCADB and consider them
    invalid, because we will not find intermediate certificate chains
    for these.
  + Output invalid PAN-OS certificate messages to stderr.
  + Display total invalid PAN-OS certificates found.

- chain.py: Fix invalid path in error.

- chain.py: Print download error to stderr.

- chain.py: Also retry on status code 502, 504.

- chain.py: Improve some messages.

- chain.py:

  Since we don't use xapi.export_result 'file', check 'content'
  instead.  There is currently an issue in pan.xapi export() where
  filename can be None.  Fixes a bug where certificate names with
  parentheses were not saved to the archive.

- chain.py: exit with status 2 when there are download failures.

- chain.py:

  + Fix missing value for format string.
  + Change message to Error.

- Documentation improvements and fixes.

0.0.0 (2024-03-15)
------------------

- Initial release.
