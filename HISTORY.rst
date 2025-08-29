Release History
===============

0.10.0 (2025-08-29)
-------------------

- etc/derailer.py: New utility program to perform vendor root CA
  program analysis.

  Currently determines vendor root store certificate counts from
  multiple sources, and can be used to verify sprocket.py stats
  counts.

- Support CCADB All Included Root Certificate Trust Bits CSV file for
  root certificate inclusion.  When utilised the equivalent of the
  SERVER_AUTHENTICATION trust bit must be set for the vendor.  The
  bits are per-vendor, and not the same as the All Certificates
  Information "Trust Bits for Root Cert" field which is a union of all
  vendors.

  To use download:
  https://ccadb.my.salesforce-sites.com/ccadb/AllIncludedRootCertsCSV
  and specify the path using the sprocket.py --trust-settings option.

- Use V3 All Certificate Information CSV
  (AllCertificateRecordsCSVFormatv3).

- chain.py: For duplicate certificate fingerprints in CCADB, retain a
  root certificate, or intermediate when no root.

- guard.py: Display count of disabled default trusted CAs for --show.

- chain.py: Don't allow intermediate certificates with null 'Derived
  Trust Bits'.

  This occurs when the intersection of an intermediate's Extended Key
  Usage (EKU) values and its root certificate trust bits are disjoint
  (empty).

- chainring.py: Add generated time to html format when verbose.

- Documentation fixes and improvements.

0.9.0 (2025-07-10)
------------------

- chainring.py: Enhance verbose html format.

  Add section headings, move certificate totals to the top, and add
  certificate tree statistics to the bottom.

- chainring.py: Move certificate tree statistics generation to
  pan_chainguard.util.stats_from_tree().

- chain.py: Don't add node to waiting nodes when parent is invalid.

  No functional change, reduces size of "Warning: nodes with no parent"
  debug log.

- Support Mozilla OneCRL for intermediate certificate exclusion.

  To use download:
  https://ccadb.my.salesforce-sites.com/mozilla/IntermediateCertsInOneCRLReportCSV
  and specify the path using the chain.py --onecrl option.

- sprocket.py: Fix bug in trust_bits usage for root certificates.

  This was using the AllCertificateRecordsCSVFormatv2 "Derived Trust
  Bits" field which only applies to intermediate certificates.  The
  "Trust Bits for Root Cert" field was recently added which provides
  trust bits for root certificates, and that is now utilised.

- ccadb.py: Add support for AllCertificateRecordsCSVFormatv2 "Trust
  Bits for Root Cert".

- chainring.py: Add format stats with preliminary data from the
  certificate tree.

- chainring.py: For html display totals when verbose.

- chainring.py: Only use bold tag when there are vendors.

- chainring.py: Add option to lookup CCADB data by certificate SHA-256
  fingerprint.

- util.py: Allow root and intermediate directory members in the
  certificates tar file.  The Python tarfile module doesn't add these
  but command-line tar command does and we may want to post-process
  the Python tar file.

0.8.0 (2025-04-13)
------------------

- guard.py: Add --show-tree, which outputs a tree created using the
  certificate subject-hash and issuer-hash configuration values.

- fling.py is deprecated.  It is recommended to use
  pan-chainguard-content or to create an up-to-date custom root store
  using sprocket.py.

- Add use cases to admin guide.

- Deprecate "google" for "chrome" in sprocket.py policy source vendor.

- chainring.py: For html format when verbose, add vendor sources for
  root certificates.

- chainring.py: Don't print Root node for format html, rst.

- guard.py: Exclude cert with Signature Algorithm: rsassaPss.

- Introduce the pan-chainguard-content repository which provides
  pre-generated, up-to-date content which can be used to simplify the
  deployment of pan-chainguard.

- chainring.py: For RST document, create reference for certificate
  fingerprint to crt.sh.

- Documentation fixes and improvements.

0.7.0 (2025-01-02)
------------------

- Major updates to guard.py:

  - Allow incremental certificate updates using --update (replaces
    --add)
  - Allow update of only root certificates
  - Add --dry-run to show what actions would be performed without
    updating PAN-OS
  - Add --show to show managed config
  - Add --update-trusted to fix out of sync trusted root CA certificate
    settings

- chainring.py: For HTML document, create hyperlink for certificate
  fingerprint to crt.sh.

- chain.py:

  For a root certificate the "Parent Certificate Name" is set to the
  "CA Owner" field; change node tag to use CA-Owner vs Issuer.  Also
  quote Subject, Issuer, CA-Owner.

- chainring.py: Add --test-collisions to test for PAN-OS certificate
  name collisions using the JSON certificate tree as input.

0.6.0 (2024-12-15)
------------------

- Split chain.py into separate programs for:

  - Intermediate certificate determination (chain.py)
  - Certificate download (link.py)

- Re-implement chain.py to use a tree (using treelib package).

- Add chainring.py to generate documents from JSON certificate tree.

- Get CA certificates program (link.py) can use alternate certificate
  sources before downloading from crt.sh.

- Allow update of root store only, without adding intermediate
  certificates.

- Certificate name on PAN-OS has been changed to
  'LINK-[0-9A-F]{26,26}' (sequence number replaced by 'LINK').

- Add tests for CCADB module.

- guard.py:

  PAN-257401 is an issue where a specific certificate, when imported
  as a device certificate and set as a trusted root CA, results in a
  commit error due to a bad signature.  Implement temporary workaround
  to not import this certificate on --add.

- sprocket.py: Fix GitHub Issue #3.

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
