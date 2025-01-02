..
 Copyright (c) 2024 Palo Alto Networks, Inc.

 Permission to use, copy, modify, and distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.

 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

pan-chainguard Administrator's Guide
====================================

.. contents::

Overview
--------

``pan-chainguard`` is a Python3 application which uses
`CCADB data
<https://www.ccadb.org/resources>`_
and allows PAN-OS SSL decryption administrators to:

#. Create a custom, up-to-date trusted root store for PAN-OS.
#. Determine intermediate certificate chains for trusted Certificate
   Authorities in PAN-OS so they can be `preloaded
   <https://wiki.mozilla.org/Security/CryptoEngineering/Intermediate_Preloading>`_
   as device certificates.

Issue 1
-------

The PAN-OS root store (*Default Trusted Certificate Authorities*) is
updated only in PAN-OS major software releases; it is not currently
managed by content updates.  The root store for PAN-OS 10.x.x releases
is now over 4 years old.

The impact for PAN-OS SSL decryption administrators is when the root
CA for the server certificate is not trusted, the firewall will
provide the forward untrust certificate to the client.  End users will
then see errors such as *NET::ERR_CERT_AUTHORITY_INVALID* (Chrome) or
*SEC_ERROR_UNKNOWN_ISSUER* (Firefox) until the missing trusted CAs are
identified, the certificates are obtained, and the certificates are
imported into PAN-OS.

Issue 2
-------

Many TLS enabled origin servers suffer from a misconfiguration in
which they:

#. Do not return intermediate CA certificates.
#. Return certificates out of order.
#. Return intermediate certificates which are not related to the root
   CA for the server certificate.

The impact for PAN-OS SSL decryption administrators is end users will
see errors such as *unable to get local issuer certificate* until the
sites that are misconfigured are
`identified
<https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/decryption/troubleshoot-and-monitor-decryption/decryption-logs/repair-incomplete-certificate-chains>`_,
the required intermediate certificates are obtained, and the
certificates are imported into PAN-OS.

Solution 1: Create Custom Root Store
------------------------------------

``pan-chainguard`` can create a custom root store, using one or more
of the major vendor root stores, which are managed by their CA
certificate program:

+ `Mozilla <https://wiki.mozilla.org/CA>`_
+ `Apple <https://www.apple.com/certificateauthority/ca_program.html>`_
+ `Microsoft <https://aka.ms/RootCert>`_
+ `Google Chrome <https://g.co/chrome/root-policy>`_

The custom root store can then be added to PAN-OS as trusted CA device
certificates.

Solution 2: Intermediate CA Preloading
--------------------------------------

``pan-chainguard`` uses a root store and the
*All Certificate Information (root and intermediate) in CCADB (CSV)*
data file as input, and determines the intermediate certificate
chains, if available, for each root CA certificate.  These can then be
added to PAN-OS as trusted CA device certificates.

By preloading known intermediates for the trusted CAs, the number of
TLS connection errors that users encounter for misconfigured servers
can be reduced, without reactive actions by an administrator.

AIA Fetching
~~~~~~~~~~~~

Another approach used is AIA fetching, or AIA chasing, which uses the
*CA Issuers* field in the *Authority Information Access* X509v3
extension of the server certificate to obtain missing issuer
certificates.  This discloses a source IP address to the CA that
issued the server certificate, which may be considered a privacy
concern.  There will also be connection delays for the certificate
download.  Intermediate CA preloading does not have these issues.  AIA
fetching is reactive, based upon what server certificates are seen;
intermediate preloading as performed by ``pan-chainguard`` is
proactive and uses a known trusted CA store as its starting point.

pan-chainguard
--------------

Install pan-chainguard
~~~~~~~~~~~~~~~~~~~~~~

The ``pan-chainguard`` source repository is hosted on GitHub at:
`https://github.com/PaloAltoNetworks/pan-chainguard
<https://github.com/PaloAltoNetworks/pan-chainguard>`_.

It requires the following Python packages:

+ `aiohttp <https://github.com/aio-libs/aiohttp>`_
+ `pan-python <https://github.com/kevinsteves/pan-python>`_
+ `treelib <https://github.com/caesar0301/treelib>`_

``pan-chainguard`` should run on any Unix system with Python 3.9 or
greater, and OpenSSL or LibreSSL; it has been tested on OpenBSD 7.6,
Ubuntu 22.04 and 24.04, and macOS 14.

Get pan-chainguard using ``git clone``
......................................

::

  $ python3 -m pip install aiohttp

  $ python3 -m pip install pan-python

  $ python3 -m pip install treelib

  $ git clone https://github.com/PaloAltoNetworks/pan-chainguard/pan-chainguard.git

  $ cd pan-chainguard

  $ bin/chain.py --version
  pan-chainguard 0.6.0

  $ bin/guard.py --version
  pan-chainguard 0.6.0

Install pan-chainguard using ``pip``
....................................

::

  $ python3 -m pip install pan-chainguard

  $ chain.py --version
  pan-chainguard 0.6.0

  $ guard.py --version
  pan-chainguard 0.6.0

pan-chainguard Command Line Programs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pan-chainguard`` provides 6 Python command line programs and a shell
script:

- ``fling.py``

  Command line program which exports the PEM encoded X.509
  certificates from the PAN-OS Default Trusted CA store.

- ``cert-fingerprints.sh``

  A shell script which takes as input the X.509 certificates
  exported by ``fling.py`` and creates a CSV file containing
  the SHA-256 fingerprint for each certificate.

- ``sprocket.py``

  Command line program which creates a custom root store according a
  user-defined policy.

- ``chain.py``

  Command line program which takes as input:

  + The root CA fingerprint CSV file created by
    ``cert-fingerprints.sh`` or ``sprocket.py``

  + The All Certificate Information (root and
    intermediate) in CCADB CSV file (`AllCertificateRecordsCSVFormatv2
    <https://www.ccadb.org/resources>`_)

  and creates:

  + A CSV file containing the fingerprints of the intermediate
    certificate chains found for the CAs in the root store

  + A JSON file containing the tree representation of the root
    and intermediate certificates

- ``chainring.py``

  Command line program which takes as input the JSON file created by
  ``chain.py`` and creates multiple representations of the certificate
  tree, including HTML and text.

- ``link.py``

  Command line program which obtains PEM encoded X.509 certificates
  from different sources including:

  + Mozilla certificates with PEM CSV files
  + Old (previous) certificate archive
  + crt.sh API

- ``guard.py``

  Command line program which takes as input the certificate archive
  created by ``link.py`` and imports the certificates (root and
  intermediate) as trusted CA device certificates on PAN-OS.

Command options can be displayed using ``--help`` (e.g.,
``chain.py --help``).

Data and Process Flow
.....................

A `data and process flow diagram
<https://github.com/PaloAltoNetworks/pan-chainguard/blob/main/doc/links.md>`_
illustrates the programs, execution sequence, and data inputs and
outputs.

pan-chainguard PAN-OS XML API Usage
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``fling.py`` and ``guard.py`` use the `pan.xapi module
<https://github.com/kevinsteves/pan-python/blob/master/doc/pan.xapi.rst>`_
to make configuration updates.

A `.panrc file
<https://github.com/kevinsteves/pan-python/blob/master/doc/panrc.rst>`_
is used to specify the hostname and API key for the PAN-OS XML API.
A `short tutorial
<http://api-lab.paloaltonetworks.com/keygen.html>`_ is available
to assist with the creation of an API key and .panrc file.

Role Based Admin
................

As a best practice it is recommended to use an application specific
role based admin for the XML API operations.  The following PAN-OS
firewall configuration creates a ``chainguard-api`` admin role profile
and ``chainguard`` admin::

   set shared admin-role chainguard-api role device xmlapi config enable
   set shared admin-role chainguard-api role device xmlapi op enable
   set shared admin-role chainguard-api role device xmlapi commit enable
   set shared admin-role chainguard-api role device xmlapi export enable
   set shared admin-role chainguard-api role device xmlapi import enable
   set shared admin-role chainguard-api role device webui
   set shared admin-role chainguard-api role device restapi

   set mgt-config users chainguard permissions role-based custom profile chainguard-api
   set mgt-config users chainguard password

.. note:: Also ensure access to all *Web UI* (webui) and *REST API*
          (restapi) features are disabled.

.. note:: Operational requests are needed because a synchronous commit
	  is used which requires ``show jobs id id-num`` to poll for
	  job completion.

The admin role profile for Panorama::

   set shared admin-role chainguard-api role panorama xmlapi config enable
   set shared admin-role chainguard-api role panorama xmlapi op enable
   set shared admin-role chainguard-api role panorama xmlapi commit enable
   set shared admin-role chainguard-api role panorama xmlapi export enable
   set shared admin-role chainguard-api role panorama xmlapi import enable
   set shared admin-role chainguard-api role panorama webui
   set shared admin-role chainguard-api role panorama restapi

When using ``guard.py`` to commit the configuration, the ``--admin``
option should be used to specify the ``pan-chainguard`` specific admin
to guarantee only changes made by the admin are committed.

Running pan-chainguard
----------------------

Identify Source Root Store
~~~~~~~~~~~~~~~~~~~~~~~~~~

``pan-chainguard`` can use a root store from PAN-OS or a custom
root store as input.

PAN-OS Root Store
.................

The PAN-OS root store (*Default Trusted Certificate Authorities*) is
updated as part of a PAN-OS major software releases; it is not
currently managed by content updates.

The root store was updated for PAN-OS 10.0, which was released in
July 2020.  All 10.x.x releases contain the same root store (10.0.x,
10.1.x and 10.2.x).

The root store was updated for PAN-OS 11.0, which was released in
November 2022.  All 11.x.x releases contain the same root store
(11.0.x, 11.1.x and 11.2.x).

To use a PAN-OS root store, run the ``fling.py`` program as described
below.

Custom Root Store
.................

You can create a custom root store, using one or more of the
major vendor root stores, which are managed by their CA certificate
program:

+ `Mozilla <https://wiki.mozilla.org/CA>`_
+ `Apple <https://www.apple.com/certificateauthority/ca_program.html>`_
+ `Microsoft <https://aka.ms/RootCert>`_
+ `Google Chrome <https://g.co/chrome/root-policy>`_

To use a custom root store, run the ``sprocket.py`` program as
described below.

sprocket.py
~~~~~~~~~~~

``sprocket.py`` is used to create a custom root store using the
following policy attributes:

#. Source vendor root store (one or more)

   + mozilla (default)
   + apple
   + microsoft
   + google

#. Set operation to use when combining multiple source sets

   + union - set of elements which are in any (default)
   + intersection - set of elements which are in all

#. `Derived Trust Bits <https://www.ccadb.org/cas/fields#formula-fields>`_
   field from CCADB

   + CLIENT_AUTHENTICATION
   + CODE_SIGNING
   + DOCUMENT_SIGNING
   + OCSP_SIGNING
   + SECURE_EMAIL
   + SERVER_AUTHENTICATION
   + TIME_STAMPING

The root store policy is specified as a JSON object; the default is:

::

   {
       "sources": ["mozilla"],
       "operation": "union",
       "trust_bits": []
   }

The following example can be used to specify a root store with
**mozilla** and **google** sources and trust bits of
**SERVER_AUTHENTICATION**:

::

   {
       "sources": ["mozilla", "google"],
       "operation": "union",
       "trust_bits": ["SERVER_AUTHENTICATION"]
   }

sprocket.py Usage
.................

::

   $ bin/sprocket.py --help
   usage: sprocket.py [options]

   create custom root store

   options:
     -h, --help            show this help message and exit
     -c PATH, --ccadb PATH
                           CCADB AllCertificateRecordsCSVFormatv2 CSV path
     -f PATH, --fingerprints PATH
                           root CA fingerprints CSV path
     --policy JSON         JSON policy object path or string
     --stats               print source stats
     --verbose             enable verbosity
     --debug {0,1,2,3}     enable debug
     --version             display version

sprocket.py Example
...................

The CCADB ``AllCertificateRecordsCSVFormatv2`` CSV file needs to be
downloaded before running ``sprocket.py``.

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ cd tmp

   $ curl -sOJ  https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2

   $ ls -lh AllCertificateRecordsReport.csv
   -rw-r--r--  1 ksteves  ksteves   7.9M Dec 10 11:56 AllCertificateRecordsReport.csv

   $ cd ..

   $ bin/sprocket.py --verbose --ccadb tmp/AllCertificateRecordsReport.csv \
   > --fingerprints tmp/root-fingerprints.csv
   policy: {'sources': ['mozilla'], 'operation': 'union', 'trust_bits': []}
   mozilla: 174 total certificates

fling.py
~~~~~~~~

``fling.py`` is used to export the PEM encoded X.509 certificates from
the PAN-OS Default Trusted CA store.  It is only used when you have
chosen to use the PAN-OS native root store; it is generally recommended
to create an up-to-date custom root store using ``sprocket.py``.

fling.py Usage
..............

::

   $ bin/fling.py --help
   usage: fling.py [options]

   export PAN-OS trusted CAs

   options:
     -h, --help          show this help message and exit
     --tag TAG, -t TAG   .panrc tagname
     --certs PATH        PAN-OS trusted CAs archive path (default: root-store.tgz)
     --xdebug {0,1,2,3}  pan.xapi debug
     --verbose           enable verbosity
     --debug {0,1,2,3}   enable debug
     --version           display version

fling.py Example
................

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ mkdir -p tmp/root-store

   $ bin/fling.py --tag pa-460-chainguard --certs tmp/root-store/root-store.tgz
   Exported 293 PAN-OS trusted CAs to tmp/root-store/root-store.tgz

   $ cd tmp/root-store/
   $ tar xzf root-store.tgz
   $ ls -1 | head
   0001_Hellenic_Academic_and_Research_Institutions_RootCA_2011.cer
   0003_USERTrust_ECC_Certification_Authority.cer
   0004_CHAMBERS_OF_COMMERCE_ROOT_-_2016.cer
   0008_VRK_Gov._Root_CA.cer
   0012_Hellenic_Academic_and_Research_Institutions_RootCA_2015.cer
   0013_SZAFIR_ROOT_CA.cer
   0014_EE_Certification_Centre_Root_CA.cer
   0016_ePKI_Root_Certification_Authority.cer
   0017_thawte_Primary_Root_CA_-_G2.cer
   0019_GeoTrust_Universal_CA_2.cer

cert-fingerprints.sh
~~~~~~~~~~~~~~~~~~~~

Run ``cert-fingerprints.sh`` if you use ``fling.py`` to export the root
store from PAN-OS.

cert-fingerprints.sh Usage
..........................

::

   $ bin/cert-fingerprints.sh --help
   usage: cert-fingerprints.sh cert-directory

cert-fingerprints.sh Example
............................

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ bin/cert-fingerprints.sh tmp/root-store > tmp/root-fingerprints.csv

   $ head tmp/root-fingerprints.csv
   "type","sha256"
   "root","BC104F15A48BE709DCA542A7E1D4B9DF6F054527E802EAA92D595444258AFE71"
   "root","4FF460D54B9C86DABFBCFC5712E0400D2BED3FBC4D4FBDAA86E06ADCD2A9AD7A"
   "root","04F1BEC36951BC1454A904CE32890C5DA3CDE1356B7900F6E62DFA2041EBAD51"
   "root","F008733EC500DC498763CC9264C6FCEA40EC22000E927D053CE9C90BFA046CB2"
   "root","A040929A02CE53B4ACF4F2FFC6981CE4496F755E6D45FE0B2A692BCD52523F36"
   "root","FABCF5197CDD7F458AC33832D3284021DB2425FD6BEA7A2E69B7486E8F51F9CC"
   "root","3E84BA4342908516E77573C0992F0979CA084E4685681FF195CCBA8A229B8A76"
   "root","C0A6F4DC63A24BFDCF54EF2A6A082A0A72DE35803E2FF5FF527AE5D87206DFD5"
   "root","A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557"

chain.py
~~~~~~~~

``chain.py`` is used to determine intermediate certificate chains for
the CAs in the root store.  It can also save the certificate metadata
as a JSON tree structure for use in generating documents which describe
the certificate hierarchy.

chain.py Usage
..............

::

   $ bin/chain.py --help
   usage: chain.py [options]

   determine intermediate CAs

   options:
     -h, --help            show this help message and exit
     -c PATH, --ccadb PATH
                           CCADB AllCertificateRecordsCSVFormatv2 CSV path
     -r PATH, --root-fingerprints PATH
                           root CA fingerprints CSV path
     -i PATH, --int-fingerprints PATH
                           intermediate CA fingerprints CSV path
     --tree PATH           save certificate tree as JSON to path
     --verbose             enable verbosity
     --debug {0,1,2,3}     enable debug
     --version             display version

chain.py Example
................

The CCADB ``AllCertificateRecordsCSVFormatv2`` CSV file needs to be
downloaded before running ``chain.py``.  If you downloaded it previously
to run ``sprocket.py`` you do not need to download it again.

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ bin/chain.py --verbose -c tmp/AllCertificateRecordsReport.csv -r tmp/root-fingerprints.csv \
   > -i tmp/intermediate-fingerprints.csv --tree tmp/certificate-tree.json
   1737 total intermediate certificates


chainring.py
~~~~~~~~~~~~

``chainring.py`` is used to create documents which describe the
certificate hierarchy in various formats including:

+ txt - Text
+ rst - reStructuredText
+ html - Hypertext Markup Language
+ json - pretty printed JSON

It is also used to test for collisions in PAN-OS certificate names,
which are derived using the first 26 characters of the certificate
SHA-256 fingerprint, which is 64 characters.

chainring.py Usage
..................

::

   $ bin/chainring.py --help
   usage: chainring.py [options]
   
   certificate tree analysis and reporting
   
   options:
     -h, --help            show this help message and exit
     --tree PATH           JSON certificate tree path
     -f {txt,rst,html,json}, --format {txt,rst,html,json}
                           output format
     -t TITLE, --title TITLE
                           report title
     --test-collisions     test for certificate name collisions
     --verbose             enable verbosity
     --debug {0,1,2,3}     enable debug
     --version             display version

chainring.py Example
....................

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ bin/chainring.py --tree tmp/certificate-tree.json --format txt > tmp/certificate-tree.txt

   $ head tmp/certificate-tree.txt
   Root
   ├── 018E13F0772532CF809BD1B17281867283FC48C6E13BE9C69812854A490C1B05 Subject: "DigiCert TLS ECC P384 Root G5" CA-Owner: "DigiCert"
   │   ├── 0215DB7E22D36D0E7535A12691A9EC0DC7F43D83AB580C0709711C1E7A9B55EC Subject: "Thawte G5 TLS ECC P-384 SHA384 2022 CA2" Issuer: "DigiCert TLS ECC P384 Root G5"
   │   ├── 07F55A105E886D191FBD2253283E77B1FC1CCDCC9F26A3E6C7E69706A7593FEF Subject: "GeoTrust EV G5 TLS CN ECC P-384 SHA384 2022 CA1" Issuer: "DigiCert TLS ECC P384 Root G5"
   │   ├── 1D75A0B37B4AE11E883C97D3FF0DC5D84D93FE129C12DD78086C4A78DAF3F709 Subject: "DigiCert Basic OV G5 TLS CN ECC P-384 SHA384 2022 CA1" Issuer: "DigiCert TLS ECC P384 Root G5"
   │   ├── 290E698939A24F7B63AB14D0490DE92BEBEF6C1C2D3BE717F3775B71C1AB626D Subject: "DigiCert Secure Site Pro EV G5 TLS CN ECC P-384 SHA384 2022 CA1" Issuer: "DigiCert TLS ECC P384 Root G5"
   │   ├── 2C171064DBFA280A1F294F72E2A1FC24C86111B23723DB9375D3004B27E7B33B Subject: "DigiCert G5 TLS EU ECC P-384 SHA384 2022 CA1" Issuer: "DigiCert TLS ECC P384 Root G5"
   │   ├── 49C1F25A88B5B15A80C1A2DA11589111C5AD8E222104FDC49022FD6AEF1CF54D Subject: "DigiCert Secure Site EV G5 TLS CN ECC P-384 SHA384 2022 CA1" Issuer: "DigiCert TLS ECC P384 Root G5"
   │   ├── 66E795550B16497E7CF4566EC63B56660F28DBD551C357C526FBB0D7620A8112 Subject: "GeoTrust G5 TLS ECC P-384 SHA384 2022 CA2" Issuer: "DigiCert TLS ECC P384 Root G5"
   │   ├── 72F104084DB7914BD8AFE6E347B9257ED4C1D7FC71D3F1E51F3CF47B739B386A Subject: "GeoTrust G5 TLS EC P-384 SHA384 2022 CA1" Issuer: "DigiCert TLS ECC P384 Root G5"

link.py
~~~~~~~

``link.py`` obtains PEM encoded X.509 certificates from different
sources including:

+ `Mozilla certificates with PEM CSV files
  <https://wiki.mozilla.org/CA/Intermediate_Certificates>`_

  * `Intermediate CA Certificates
    <https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV>`_

  * `Non-revoked, non-expired Intermediate CA Certificates chaining up to
    roots in Mozilla's program with the Websites trust bit set
    <https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport>`_

+ Old (previous) certificate archive

+ crt.sh API

The `crt.sh API <https://crt.sh/>`_ can be slow.  ``link.py``
implements concurrent API requests using asyncio, however the server
throttles response times in addition to returning "429 Too many
requests" response status when too many concurrent requests are
performed.  Timeout, connection and response content errors have also
been observed, and when seen will be retried up to 4 times (total 5
tries).

Updating (or refreshing) the certificate archive only needs to be
performed periodically when the root store is updated by
``sprocket.py`` and/or ``chain.py`` is used to determine intermediate
certificates for updates in CCADB.

link.py Usage
.............

::

   $ bin/link.py --help
   usage: link.py [options]
   
   get CA certificates
   
   options:
     -h, --help            show this help message and exit
     -f PATH, --fingerprints PATH
                           CA fingerprints CSV path
     -m PATH, --certs-mozilla PATH
                           Mozilla certs with PEM CSV path
     --certs-old PATH      old certificate archive path
     --certs-new PATH      new certificate archive path
     --verbose             enable verbosity
     --debug {0,1,2,3}     enable debug
     --version             display version

link.py Example
................

This example performs an initial download without an old certificate
archive.

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ cd tmp

   $ rm -f MozillaIntermediateCerts.csv 
   $ curl -sOJ https://ccadb.my.salesforce-sites.com/mozilla/MozillaIntermediateCertsCSVReport

   $ rm -f PublicAllIntermediateCertsWithPEMReport.csv
   $ curl -sOJ https://ccadb.my.salesforce-sites.com/mozilla/PublicAllIntermediateCertsWithPEMCSV

   $ cd ..

   $ bin/link.py --verbose -f tmp/root-fingerprints.csv -f tmp/intermediate-fingerprints.csv \
   > -m tmp/MozillaIntermediateCerts.csv -m tmp/PublicAllIntermediateCertsWithPEMReport.csv \
   > --certs-old tmp/certificates-old.tgz --certs-new tmp/certificates-new.tgz >tmp/stdout.txt 2>tmp/stderr.txt

   $ echo $?
   0

   $ tail tmp/stdout.txt 
   Download using crt.sh API 55903859C8C0C3EBB8759ECE4E2557225FF5758BBD38EBD48276601E1BD58097
   Download using crt.sh API ADA5A71AF2121B569104BE385E746FA975617E81DBFAF6F722E62352471BD838
   Download using crt.sh API E7FA0F67C9B6D886C868408996DBDFC3680E8B9EC47628EEFB4824C23A287693
   Download using crt.sh API D793D934DD1B9FF9F6A76D438C760ED44B72BCDE660B49A77DBCF81EC7CEB3A9
   Download using crt.sh API F7B09EEA79096A4498F6A2B8D6F1183228A3769EA988050D1B32A380EABC4F9E
   certs-old: 0
   MozillaIntermediateCerts: 1718
   PublicAllIntermediateCerts: 15
   crt.sh: 178
   Total certs-new: 1911

``link.py`` exits with the following status codes:

===========  =========
Status Code  Condition
===========  =========
0            success, all certificates were obtained
1            fatal error
2            error, some certificates were not obtained
===========  =========

Review ``tmp/stderr.txt`` for warnings and errors.

The tar archive uses the following directory structure:

::

   root/
     certificate-SHA-256.pem
   intermediate/
     certificate-SHA-256.pem

For example:

::

   $ tar tzf tmp/certificates-new.tgz | head
   root/55926084EC963A64B96E2ABE01CE0BA86A64FBFEBCC7AAB5AFC155B37FD76066.pem
   root/2E44102AB58CB85419451C8E19D9ACF3662CAFBC614B6A53960A30F7D0E2EB41.pem
   root/8ECDE6884F3D87B1125BA31AC3FCB13D7016DE7F57CC904FE1CB97C6AE98196E.pem
   root/1BA5B2AA8C65401A82960118F80BEC4F62304D83CEC4713A19C39C011EA46DB4.pem
   root/18CE6CFE7BF14E60B2E347B8DFE868CB31D02EBB3ADA271569F50343B46DB3A4.pem
   root/E35D28419ED02025CFA69038CD623962458DA5C695FBDEA3C22B0BFB25897092.pem
   root/568D6905A2C88708A4B3025190EDCFEDB1974A606A13C6E5290FCB2AE63EDAB5.pem
   root/D8E0FEBC1DB2E38D00940F37D27D41344D993E734B99D5656D9778D4D8143624.pem
   root/6B328085625318AA50D173C98D8BDA09D57E27413D114CF787A0F5D06C030CF6.pem
   root/5C58468D55F58E497E743982D2B50010B6D165374ACF83A7D4A32DB768C4408E.pem

This example performs a subsequent download using an old certificate
archive.

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ cd tmp

   $ mv certificates-new.tgz certificates-old.tgz

   $ cd ..

   $ bin/link.py --verbose -f tmp/root-fingerprints.csv -f tmp/intermediate-fingerprints.csv \
   > --certs-old tmp/certificates-old.tgz --certs-new tmp/certificates-new.tgz
   certs-old: 1911
   MozillaIntermediateCerts: 0
   PublicAllIntermediateCerts: 0
   crt.sh: 0
   Total certs-new: 1911

guard.py
~~~~~~~~

guard.py Usage
..............

::

   $ bin/guard.py --help
   usage: guard.py [options]

   update PAN-OS trusted CAs

   options:
     -h, --help            show this help message and exit
     --tag TAG, -t TAG     .panrc tagname
     --vsys VSYS           vsys name or number
     --template TEMPLATE   Panorama template
     --certs PATH          certificate archive path
     --update              update certificates
     --delete              delete all previously added certificates
     -T {root,intermediate}, --type {root,intermediate}
                           certificate type(s) for update
     --update-trusted      update trusted root CA for all certificates
     --commit              commit configuration
     --dry-run             don't update PAN-OS
     --show                show pan-chainguard managed config
     --admin ADMIN         commit admin
     --xdebug {0,1,2,3}    pan.xapi debug
     --verbose             enable verbosity
     --debug {0,1,2,3}     enable debug
     --version             display version

guard.py Example
................

``guard.py`` uses the certificate archive created by ``link.py`` to
import the certificates as trusted CA device certificates on PAN-OS:

+ ``--tag`` specifies the .panrc tagname which can be a Panorama or
  firewall.

+ ``--template`` is used to specify the Panorama template to update.

+ ``--vsys`` is used to specify the vsys for multi VSYS firewalls and
  multi VSYS Panorama templates.

+ ``--delete`` is used to delete all previously added certificates.

+ ``--update`` is used to perform an initial update or incremental
  update of certificates.

+ ``--certs`` specifies the certificate archive for the update.

+ ``--type`` specifies the certificate type(s) for the update:

  * root - update only root certificates; this is used to update the
    default PAN-OS root store with a custom root store.

  * root and intermediate - update root and intermediate certificates;
    this is used to update the default PAN-OS root store with a custom
    root store and their intermediate certificates.

  * intermediate - update only intermediate certificates.

+ ``--dry-run`` is used to show what actions ``guard.py`` would
  perform without updating PAN-OS.

+ ``--show`` is used the show the pan-chainguard managed
  configuration.

The device certificate names can have a maximum length of 31
characters on Panorama and 63 on PAN-OS.  They are constructed in a
way to avoid conflict with other user and machine defined certificate
names, and also to have a well-defined pattern so ``guard.py`` can
manage certificates it owns.  The PAN-OS certificate name pattern
(format) used is:

+ The length is 31 characters (the maximum length on Panorama)

+ Starts with 'LINK'

+ Followed by a single dash '-'

+ Followed by the first 26 characters of the uppercase hexadecimal
  certificate fingerprint

.. note:: ``chainring.py --test-collisions`` can be used to test for
          collisions in PAN-OS certificate names.

.. note:: Panorama support:

	  + import to Panorama device certificates
	  + import to Template single VSYS device certificates
	  + import to Template multi VSYS device certificates
	    (currently does not work due to PAN-257229)
	  + commit to Panorama

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ bin/guard.py -t pa-460-chainguard --show
   0 Device Certificates

   $ bin/guard.py -t pa-460-chainguard --update -T root -T intermediate \
   > --certs tmp/certificates-new.tgz --dry-run
   update dry-run: 0 to delete, 1911 to add

   $ bin/guard.py -t pa-460-chainguard --update -T root -T intermediate \
   > --certs tmp/certificates-new.tgz --commit
   0 certificates deleted
   1911 certificates added
   commit: success

   $ bin/guard.py -t pa-460-chainguard --update -T root -T intermediate \
   > --certs tmp/certificates-new.tgz --dry-run
   update dry-run: 0 to delete, 0 to add

   $ bin/guard.py -t pa-460-chainguard --show
   1911 Device Certificates
   1911 Trusted Root CA Certificates

About the Name
--------------

``pan-chainguard`` is named after a bicycle chain guard.  This chain
guard serves to guard and protect against an out-of-date root store
and missing intermediate certificate chains.  ``fling.py`` is named
after anti-fling grease used on chains.

References
----------

- `PAN-OS Repair Incomplete Certificate Chains
  <https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/decryption/troubleshoot-and-monitor-decryption/decryption-logs/repair-incomplete-certificate-chains>`_

- `pan-chainguard GitHub Repository
  <https://github.com/PaloAltoNetworks/pan-chainguard>`_

- `Common CA Database - Useful Resources
  <https://www.ccadb.org/resources>`_

- `pan-python
  <https://github.com/kevinsteves/pan-python>`_

- `Firefox Intermediate CA Preloading
  <https://wiki.mozilla.org/Security/CryptoEngineering/Intermediate_Preloading>`_

- `crt.sh API Usage
  <https://groups.google.com/g/crtsh/c/puZMuqBaWOE>`_

- `Mozilla CA/Intermediate Certificates
  <https://wiki.mozilla.org/CA/Intermediate_Certificates>`_
