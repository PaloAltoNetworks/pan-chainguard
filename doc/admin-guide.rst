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
to derive intermediate certificate chains for trusted
certificate authorities in PAN-OS so they can be
`preloaded
<https://wiki.mozilla.org/Security/CryptoEngineering/Intermediate_Preloading>`_
as device certificates.

Problem
-------

Many TLS enabled origin servers suffer from a misconfiguration in
which they:

#. Do not return intermediate CA certificates.
#. Return certificates out of order.
#. Return intermediate certificates which are not related to the CA
   which signed the server certificate.

The impact for PAN-OS SSL decryption administrators is end users will
see errors such as *unable to get local issuer certificate* until the
sites that are misconfigured are
`identified
<https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/decryption/troubleshoot-and-monitor-decryption/decryption-logs/repair-incomplete-certificate-chains>`_,
the required intermediate certificates are obtained, and the
certificates are imported into PAN-OS.

Solution: Intermediate CA Preloading
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

``pan-chainguard`` should run on any Unix system with Python 3.9 or
greater, and OpenSSL or LibreSSL; it has been tested on OpenBSD 7.5,
Ubuntu 22.04 and macOS 14.

Get pan-chainguard using ``git clone``
......................................

::

  $ python3 -m pip install aiohttp

  $ python3 -m pip install pan-python

  $ git clone https://github.com/PaloAltoNetworks/pan-chainguard/pan-chainguard.git

  $ cd pan-chainguard

  $ bin/chain.py --version
  pan-chainguard 0.4.0

  $ bin/guard.py --version
  pan-chainguard 0.4.0

Install pan-chainguard using ``pip``
....................................

::

  $ python3 -m pip install pan-chainguard

  $ chain.py --version
  pan-chainguard 0.4.0

  $ guard.py --version
  pan-chainguard 0.4.0

pan-chainguard Command Line Programs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pan-chainguard`` provides 4 Python command line programs and a shell
script:

- ``fling.py``

  Command line program which exports the PEM encoded X.509
  certificates from the PAN-OS Default Trusted CA store.

- ``cert-fingerprints.sh``

  A shell script which takes as input the X.509 certificates
  exported by ``fling.py`` and creates a CSV file containing
  the SHA-256 fingerprint for each certificate.

- ``sprocket.py``

  Command line program which can be used to create a custom root store
  according a user-defined policy.

- ``chain.py``

  Command line program which takes as input:

  + The certificate fingerprint CSV file created by
    ``cert-fingerprints.sh`` or ``sprocket.py``

  + The All Certificate Information (root and
    intermediate) in CCADB CSV file (`AllCertificateRecordsCSVFormatv2
    <https://www.ccadb.org/resources>`_)

  and creates a tar archive containing the intermediate certificate
  chains found for the CAs in the root store.

- ``guard.py``

  Command line program which takes as input the certificate archive
  created by ``chain.py`` and imports the intermediate certificates as
  trusted CA device certificates on PAN-OS.

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

``sprocket.py`` is used to create a customised root store using the
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

   create custom root store from CCADB

   options:
     -h, --help            show this help message and exit
     -c PATH, --ccadb PATH
                           CCADB AllCertificateRecordsCSVFormatv2 CSV path
     -f PATH, --fingerprints PATH
                           root store fingerprints CSV path
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
   -rw-r--r--  1 ksteves  ksteves   7.1M Jul 14 10:39 AllCertificateRecordsReport.csv

   $ cd ..

   $ bin/sprocket.py --verbose --ccadb tmp/AllCertificateRecordsReport.csv \
   > --fingerprints tmp/cert-fingerprints2.csv
   policy: {'sources': ['mozilla'], 'operation': 'union', 'trust_bits': []}
   mozilla: 171 total certificates

fling.py
~~~~~~~~

Use ``fling.py`` to export a PAN-OS root store.

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

   $ bin/cert-fingerprints.sh tmp/root-store > tmp/cert-fingerprints.csv

   $ head tmp/cert-fingerprints.csv
   "filename","sha256"
   "0001_Hellenic_Academic_and_Research_Institutions_RootCA_2011.cer","BC104F15A48BE709DCA542A7E1D4B9DF6F054527E802EAA92D595444258AFE71"
   "0003_USERTrust_ECC_Certification_Authority.cer","4FF460D54B9C86DABFBCFC5712E0400D2BED3FBC4D4FBDAA86E06ADCD2A9AD7A"
   "0004_CHAMBERS_OF_COMMERCE_ROOT_-_2016.cer","04F1BEC36951BC1454A904CE32890C5DA3CDE1356B7900F6E62DFA2041EBAD51"
   "0008_VRK_Gov._Root_CA.cer","F008733EC500DC498763CC9264C6FCEA40EC22000E927D053CE9C90BFA046CB2"
   "0012_Hellenic_Academic_and_Research_Institutions_RootCA_2015.cer","A040929A02CE53B4ACF4F2FFC6981CE4496F755E6D45FE0B2A692BCD52523F36"
   "0013_SZAFIR_ROOT_CA.cer","FABCF5197CDD7F458AC33832D3284021DB2425FD6BEA7A2E69B7486E8F51F9CC"
   "0014_EE_Certification_Centre_Root_CA.cer","3E84BA4342908516E77573C0992F0979CA084E4685681FF195CCBA8A229B8A76"
   "0016_ePKI_Root_Certification_Authority.cer","C0A6F4DC63A24BFDCF54EF2A6A082A0A72DE35803E2FF5FF527AE5D87206DFD5"
   "0017_thawte_Primary_Root_CA_-_G2.cer","A4310D50AF18A6447190372A86AFAF8B951FFB431D837F1E5688B45971ED1557"

chain.py
~~~~~~~~

chain.py Usage
..............

::

   $ bin/chain.py --help
   usage: chain.py [options]

   generate intermediate CAs to preload

   options:
     -h, --help            show this help message and exit
     -c PATH, --ccadb PATH
                           CCADB AllCertificateRecordsCSVFormatv2 CSV path
     -f PATH, --fingerprints PATH
                           root CAs fingerprints CSV path
     --certs PATH          certificate archive path (default: certificates.tgz)
     --roots               also download root CAs
     --verbose             enable verbosity
     --debug {0,1,2,3}     enable debug
     --version             display version

chain.py Example
................

The CCADB ``AllCertificateRecordsCSVFormatv2`` CSV file needs to be
downloaded before running ``chain.py``.  If you downloaded it previously
to run ``sprocket.py`` you do not need to download it again.

``chain.py`` is the most time consuming part of the process, because
it downloads all required intermediate certificates, and optionally
the root certificates, using the `crt.sh API <https://crt.sh/>`_,
which is slow.

``chain.py`` implements concurrent API requests using asyncio, however
the server throttles response times in addition to returning "429 Too
many requests" response status when too many concurrent requests are
performed.  Timeout, connection and response content errors have also
been observed, and when seen will be retried up to 4 times.

The intermediate certificate archive only needs to be created
periodically, and then can be used by ``guard.py`` to update
the certificates on multiple PAN-OS instances with the same major
version.

When using a custom root store, specify the ``--roots`` option to
also download the root CA certificates.

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ cd tmp

   $ curl -sOJ  https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2

   $ ls -lh AllCertificateRecordsReport.csv
   -rw-r--r--  1 ksteves  ksteves   7.1M Jul 14 10:39 AllCertificateRecordsReport.csv

   $ cd ..

   $ bin/chain.py --ccadb tmp/AllCertificateRecordsReport.csv --fingerprints tmp/cert-fingerprints.csv \
   > --certs tmp/certificates.tgz 2>tmp/stderr.txt
   21 invalid certificates found
   182 intermediate chains found for 272 root CAs
   All 182 certificate chains were downloaded successfully

   $ echo $?
   0

``chain.py`` exits with the following status codes:

===========  =========
Status Code  Condition
===========  =========
0            success, all certificates were downloaded
1            fatal error
2            error, some certificates were not downloaded
===========  =========

Review ``tmp/stderr.txt`` for warnings and errors.

The tar archive uses the following directory structure:

::

   PAN-OS root certificate name/
     root/
       certificate-SHA-256.crt
     intermediate/
       certificate-SHA-256.crt

For example:

::

   $ tar tzf tmp/certificates.tgz 0555_Certum_Trusted_Root_CA
   0555_Certum_Trusted_Root_CA/root/FE7696573855773E37A95E7AD4D9CC96C30157C15D31765BA9B15704E1AE78FD.crt
   0555_Certum_Trusted_Root_CA/intermediate/83C0A5A76844C840DFAF820FFD02ADF6573A26823EF6AF758A3384A0AC044083.crt
   0555_Certum_Trusted_Root_CA/intermediate/1C4EEA3A47ABD122568EAB547E06B52111F7F388662C246C8ECBE2660B9F26F1.crt
   0555_Certum_Trusted_Root_CA/intermediate/4736F1ECF26A043CB4D8F94DA8302EA9E45F3D311048F3A400D01AEED1E99444.crt
   0555_Certum_Trusted_Root_CA/intermediate/F54CE21EA0F79548F1201A619049CA15F065E49A69F26FB9CF1282C7EECF9C4C.crt
   0555_Certum_Trusted_Root_CA/intermediate/EF3653AC5056AA4C6EF72AA922F43DAF750CA901AD1198FEA1B81E0D10B51E0A.crt
   0555_Certum_Trusted_Root_CA/intermediate/43EDFB2C7C93E63D6566D240EB9C69CFF5C0D5C996C4AC9BCC9CE75828C3B9BE.crt
   0555_Certum_Trusted_Root_CA/intermediate/AA0C4B7801B09FB77E423C91331EFB62A5A2A8B23A9D7C997E6A9BEEA435D2BF.crt
   0555_Certum_Trusted_Root_CA/intermediate/B5C87A0B2239DAFE0A5285E340626269ACA5E90F57492C38E9050CA5D18BC21A.crt
   0555_Certum_Trusted_Root_CA/intermediate/509ABBB92864C2C44D7CBC466B63950E350165EE772A3037AE8168E92226A46F.crt
   0555_Certum_Trusted_Root_CA/intermediate/D79F1F0C8141804B39D04B2592D57AFEBE74F9460654AFF491490DBB7C5A2D74.crt
   0555_Certum_Trusted_Root_CA/intermediate/B5D46DC027130E5CED3BE5083EB34028DD9230F4D5A36AD1924D21C0EF984CBA.crt

guard.py
~~~~~~~~

guard.py Usage
..............

::

   $ bin/guard.py --help
   usage: guard.py [options]

   preload intermediate CAs

   options:
     -h, --help           show this help message and exit
     --tag TAG, -t TAG    .panrc tagname
     --vsys VSYS          vsys name or number
     --template TEMPLATE  Panorama template
     --certs PATH         certificate archive path (default: certificates.tgz)
     --add                add intermediate certificates
     --add-roots          add root certificates
     --delete             delete previously added certificates
     --disable-trusted    disable all default trusted root CAs
     --enable-trusted     enable all default trusted root CAs
     --commit             commit configuration
     --admin ADMIN        commit admin
     --xdebug {0,1,2,3}   pan.xapi debug
     --verbose            enable verbosity
     --debug {0,1,2,3}    enable debug
     --version            display version

guard.py Example
................

``guard.py`` uses the certificate archive created by ``chain.py`` to
import the intermediate certificates, and optionally the root
certificates, as trusted CA device certificates on PAN-OS.  The .panrc
tagname can specify a Panorama, firewall or multi-vsys firewall.
``--vsys`` is used to specify the vsys for multi-vsys firewalls.
``--template`` is used to specify the Panorama template to update.
``--delete`` is used to delete previously added certificates and when
used with ``--add`` will perform an update of the existing
intermediate certificates.  ``--add-roots`` is used to add root
certificates from the archive, and when used with
``--disable-trusted`` replaces the PAN-OS root store with a custom
root store.

The device intermediate certificate names are constructed in a way
that they should be unique and not conflict with other certificate
names:

+ The length is 31 characters (the maximum length on Panorama)

+ Starts with:

  - PAN-OS root store: 4 digit PAN-OS root certificate sequence number
  - Custom root store: 4 digit sequence number 9001-9999

+ Followed by a single dash '-'

+ Followed by the first 26 characters of the uppercase hexadecimal
  certificate fingerprint

.. note:: Panorama support includes:

	  + import to Panorama device certificates
	  + import to Template shared device certificates
	  + commit to Panorama

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ bin/guard.py --tag pa-460-chainguard --admin chainguard --vsys 2 --certs tmp/certificates.tgz \
   > --delete --add --commit
   201 certificates deleted
   201 intermediate certificates added
   commit: success

About the Name
--------------

``pan-chainguard`` is named after a bicycle chain guard.  This chain
guard serves to guard and protect against missing intermediate
certificate chains.  ``fling.py`` is named after anti-fling grease
used on chains.

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
