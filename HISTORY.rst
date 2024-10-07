Release History
===============

0.5.0 (2024-10-07)
------------------

- chain.py: Fix bug where only a single child certificate chain for a
  root was used.

- Add To Do List.

- guard.py: When API import results in expired certificate error, skip
  that certificate.  Allows use of an older certificate archive.

- chain.py: Remove unneeded else.

- chain.py: Raise debug level to 3 for revoked and expired logging.

- chain.py: Fix incorrect indent for saving 'Intermediate with no
  parent' certificate.

- Add features to allow a custom root store to replace the PAN-OS root
  store.

0.4.0 (2024-07-12)
------------------

- ccadb.py: Add functions for 'Derived Trust Bits' to ccadb module.

- chain.py: Set user-agent header to pan-chainguard/version for crt.sh
  API.

- chain.py, guard.py: Generalise some message strings previously
  specifying PAN-OS to prepare for using other root stores as input.

- chain.py, ccadb.py: Add pan_chainguard.ccadb module.

- Documentation improvements and fixes.

0.3.0 (2024-06-12)
------------------

- guard.py: Cache certificate names so we can use a single API request
  to enable them as trusted root CAs.

- guard.py: When device is panorama and template specified, perform
  partial commit with template scope.

- chain.py: Also retry download on 503 Service Unavailable.

- guard.py: Fix partial commit using specific admin.  In the XML cmd
  document, <admin> needs to be within <partial> container.

- guard.py: Simplify Xpath() class.

- admin-guide.rst:

  chainguard-api admin profile does require type=op because we use
  synchronous commit in pan.xapi which uses 'show jobs id id-num' to
  check job status.

- guard.py: Fix use of panorama from removal of global.

0.2.0 (2024-05-30)
------------------

- guard.py: Add support for import to Panorama Template shared device
  certificates.

- chain.py:

  Change 'Server Authentication' not in 'Derived Trust Bits' check to
  a warning.  Safer to leave these valid until we can research this
  more.

- Documentation improvements and fixes:

  + type=op not needed in admin role profile.

  + Add admin role profile for Panorama.

  + Document intermediate certificate name pattern.

  + There is a single *All Certificate Information (root and
    intermediate) in CCADB (CSV)* data file now.

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
