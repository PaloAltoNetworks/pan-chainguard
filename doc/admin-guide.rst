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

``pan-chainguard`` uses the PAN-OS default trusted CA store and the
*All Certificate Information* CCADB data file as input, and determines
the intermediate certificate chains, if available, for each root CA
certificate.  These can then be added to PAN-OS as trusted CA device
certificates.

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
greater, and OpenSSL or LibreSSL; it has been tested on OpenBSD 7.4,
Ubuntu 22.04 and macOS 14.

Get pan-chainguard using ``git clone``
......................................

::

  $ python3 -m pip install aiohttp

  $ python3 -m pip install pan-python

  $ git clone https://github.com/PaloAltoNetworks/pan-chainguard/pan-chainguard.git

  $ cd pan-chainguard

  $ bin/chain.py --version
  pan-chainguard 0.0.0

  $ bin/guard.py --version
  pan-chainguard 0.0.0

Install pan-chainguard using ``pip``
....................................

::

  $ python3 -m pip install pan-chainguard

  $ chain.py --version
  pan-chainguard 0.0.0

  $ guard.py --version
  pan-chainguard 0.0.0

pan-chainguard Command Line Programs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pan-chainguard`` provides 3 Python command line programs and a shell
script:

- ``fling.py``

  Command line program which exports the PEM encoded X.509
  certificates from the PAN-OS Default Trusted CA store.

- ``cert-fingerprints.sh``

  A shell script which takes as input the X.509 certificates
  exported by ``fling.py`` and creates a CSV file containing
  the SHA-256 fingerprint for each certificate.

- ``chain.py``

  Command line program which takes as input:

  + The certificate fingerprint CSV file created by
    ``cert-fingerprints.sh``

  + The Version 2 All Certificate Information (root and
    intermediate) CCADB CSV file (`AllCertificateRecordsCSVFormatv2
    <https://www.ccadb.org/resources>`_)

  and creates a tar archive containing the intermediate certificate
  chains found for the PAN-OS trusted root CAs.

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
configuration creates a ``chainguard-api`` role and ``chainguard``
admin::

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

When using ``guard.py`` to commit the configuration, the ``--admin``
option should be used to specify the ``pan-chainguard`` specific admin
to guarantee only changes made by the admin are committed.

Running pan-chainguard
----------------------

fling.py
~~~~~~~~

fling.py Usage
..............

::

   $ bin/fling.py --help
   usage: fling.py [options]

   export PAN-OS trusted CAs

   options:
     -h, --help          show this help message and exit
     --tag TAG, -t TAG   .panrc tagname
     --certs PATH        PAN-OS trusted CAs archive path (default: trust-store.tgz)
     --xdebug {0,1,2,3}  pan.xapi debug
     --verbose           enable verbosity
     --version           display version

fling.py Example
................

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ mkdir -p tmp/trust-store

   $ bin/fling.py --tag pa-460-chainguard --certs tmp/trust-store/trust-store.tgz
   Exported 288 PAN-OS trusted CAs to tmp/trust-store/trust-store.tgz

   $ cd tmp/trust-store/
   $ tar xzf trust-store.tgz
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

   $ bin/cert-fingerprints.sh tmp/trust-store > tmp/cert-fingerprints.csv

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

   generate PAN-OS intermediate CAs to preload

   options:
     -h, --help            show this help message and exit
     -c PATH, --ccadb PATH
                           CCADB AllCertificateRecordsCSVFormatv2 CSV path
     -f PATH, --fingerprints PATH
                           PAN-OS trusted CAs fingerprints CSV path
     --certs PATH          certificate archive path (default: certificates.tgz)
     --roots               also download root CAs (experimental)
     --verbose             enable verbosity
     --version             display version

chain.py Example
................

The CCADB ``AllCertificateRecordsCSVFormatv2`` CSV file needs to be
downloaded before running ``chain.py``.

``chain.py`` is the most time consuming part of the process, because
it downloads all required intermediate certificates, and optionally
the root certificates for an experimental option in ``guard.py``,
using the `crt.sh API <https://crt.sh/>`_, which is slow.

``chain.py`` implements concurrent API requests using asyncio, however
the server throttles response times in addition to returning "429 Too
many requests" response status when too many concurrent requests are
performed.  Timeout, connection and response content errors have also
been observed, and when seen will be retried up to 4 times.

The intermediate certificate archive only needs to be created
periodically, and then can be used by ``guard.py`` to update
the certificates on multiple PAN-OS instances with the same major
version.

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ cd tmp

   $ curl -OJ  https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2
     % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                    Dload  Upload   Total   Spent    Left  Speed
   100 6041k    0 6041k    0     0   138k      0 --:--:--  0:00:43 --:--:--  919k

   $ ls -lh AllCertificateRecordsReport.csv
   -rw-r--r--  1 ksteves  ksteves   5.9M Jan 16 17:14 AllCertificateRecordsReport.csv

   $ cd ..

   $ bin/chain.py --ccadb tmp/AllCertificateRecordsReport.csv --fingerprints tmp/cert-fingerprints.csv --certs tmp/certificates.tgz 2>tmp/stderr.txt
   Invalid PAN-OS certificate 0008_VRK_Gov._Root_CA.cer: Expired (valid to 2023.12.18) F008733EC500DC498763CC9264C6FCEA40EC22000E927D053CE9C90BFA046CB2 VRK Gov. Root CA
   Invalid PAN-OS certificate 0020_Staat_der_Nederlanden_EV_Root_CA.cer: Expired (valid to 2022.12.08) 4D2491414CFE956746EC4CEFA6CF6F72E28A1329432F9D8A907AC4CB5DADC15A Staat der Nederlanden EV Root CA
   Invalid PAN-OS certificate 0026_Izenpe.com.cer: Revoked 23804203CA45D8CDE716B8C13BF3B448457FA06CC10250997FA01458317C41E5 Izenpe.com
   Invalid PAN-OS certificate 0035_TRKTRUST_Elektronik_Sertifika_Hizmet_Salaycs_H5.cer: Expired (valid to 2023.04.28) 49351B903444C185CCDC5C693D24D8555CB208D6A8141307699F4AF063199D78 TÜRKTRUST Elektronik Sertifika Hizmet Sağlayıcısı H5
   Invalid PAN-OS certificate 0057_Security_Communication_RootCA1.cer: Expired (valid to 2023.09.30) E75E72ED9F560EEC6EB4800073A43FC3AD19195A392282017895974A99026B6C SECOM Trust.net - Security Communication RootCA1
   Invalid PAN-OS certificate 0125_ACNLB.cer: Expired (valid to 2023.05.15) 894CE6DDB012CB3F736954668DE63F436080E95F17B7A81BD924EB21BEE9E440 ACNLB
   Invalid PAN-OS certificate 0153_Trustis_FPS_Root_CA.cer: Expired (valid to 2024.01.21) C1B48299ABA5208FE9630ACE55CA68A03EDA5A519C8802A0D3A673BE8F8E557D Trustis Limited - Trustis FPS Root CA
   Invalid PAN-OS certificate 0201_POSTArCA.cer: Expired (valid to 2023.02.07) 007E452FD5CF838946696DFE37A2DB2EF3991436D27BCBAB45922053C15A87A8 POSTarCA
   Invalid PAN-OS certificate 0231_Autoridade_Certificadora_Raiz_Brasileira_v2.cer: Expired (valid to 2023.06.21) FB47D92A9909FD4FA9BEC02737543E1F3514CED747407A8D9CFA397B0915067C Autoridade Certificadora Raiz Brasileira v2
   Invalid PAN-OS certificate 0244_Hongkong_Post_Root_CA_1.cer: Expired (valid to 2023.05.15) F9E67D336C51002AC054C632022D66DDA2E7E3FFF10AD061ED31D8BBB410CFB2 Hongkong Post Root CA 1
   Invalid PAN-OS certificate 0305_E-Tugra_Certification_Authority.cer: Expired (valid to 2023.03.03) B0BFD52BB0D7D9BD92BF5D4DC13DA255C02C542F378365EA893911F55E55F23C E-Tugra Certification Authority
   Invalid PAN-OS certificate 0324_A-Trust-Root-05.cer: Expired (valid to 2023.09.20) 2DDE9D0C0A90E7B32B5ABC01F41799D42E95A1E3C31C3B39373BB8141EA54471 A-Trust-Root-05
   179 intermediate chains found for 276 PAN-OS trusted CAs
   download 0001_Hellenic_Academic_and_Research_Institutions_RootCA_2011 intermediates 1
   download 0003_USERTrust_ECC_Certification_Authority intermediates 1
   download 0012_Hellenic_Academic_and_Research_Institutions_RootCA_2015 intermediates 1
   download 0014_EE_Certification_Centre_Root_CA intermediates 1
   download 0016_ePKI_Root_Certification_Authority intermediates 1
   download 0017_thawte_Primary_Root_CA_-_G2 intermediates 1
   download 0019_GeoTrust_Universal_CA_2 intermediates 1
   download 0021_OISTE_WISeKey_Global_Root_GB_CA intermediates 1
   [...]

``chain.py`` exits with the following status codes:

===========  =========
Status Code  Condition
===========  =========
0            success, all certificates were downloaded
1            fatal error
2            error, some certificates were not downloaded
===========  =========

Review ``tmp/stderr.txt`` for warnings and errors; in the normal case
it will be empty:

::

   $ ls -l tmp/stderr.txt
   -rw-r--r--  1 ksteves  ksteves  0 Mar 11 16:15 tmp/stderr.txt

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
   0555_Certum_Trusted_Root_CA/intermediate/1C4EEA3A47ABD122568EAB547E06B52111F7F388662C246C8ECBE2660B9F26F1.crt

guard.py
~~~~~~~~

guard.py Usage
..............

::

   $ bin/guard.py --help
   usage: guard.py [options]

   preload PAN-OS intermediate CAs

   options:
     -h, --help          show this help message and exit
     --tag TAG, -t TAG   .panrc tagname
     --vsys VSYS         vsys name or number
     --certs PATH        PAN-OS certificate archive path (default: certificates.tgz)
     --add               add intermediate certificates
     --add-roots         add root certificates (experimental)
     --delete            delete previously added certificates
     --commit            commit configuration
     --admin ADMIN       commit admin
     --xdebug {0,1,2,3}  pan.xapi debug
     --verbose           enable verbosity
     --version           display version

guard.py Example
................

``guard.py`` uses the certificate archive created by ``chain.py`` to
import the intermediate certificates as trusted CA device certificates
on PAN-OS.  The .panrc tagname can specify a Panorama, firewall or
multi-vsys firewall.  ``--vsys`` is used to specify the vsys for
multi-vsys firewalls.

.. note:: ``--add-roots`` is an experimental option which is known
	  to cause a commit failure.

.. note:: Panorama support is limited and currently the Panorama
	  device certificates are updated as a first step; support for
	  templates and vsys can be added in the future.  Also commit
	  implements commit to Panorama; it is unlikely commit and
	  push will be added.

::

   $ pwd
   /home/ksteves/git/pan-chainguard

   $ bin/guard.py --tag pa-460-chainguard --admin chainguard --vsys 2 --certs tmp/certificates.tgz \
   > --delete --add --commit
   201 certificates deleted
   201 intermediate certificates added
   commit config for admin chainguard
   commit: success: "Partial changes to commit: changes to configuration by all administrators
   Changes to vsys configuration: (vsys2)
   Configuration committed successfully
   Local configuration size: 617 KB
   Predefined configuration size: 17 MB
   Merged configuration size(local, panorama pushed, predefined): 18 MB
   Maximum recommended merged configuration size: 35 MB (51% configured)"

PAN-OS Trusted CA Store Updates
-------------------------------

The PAN-OS Trusted CA Store is updated as part of a PAN-OS software
release; it is not currently managed by content updates.  The
certificate store was updated on PAN-OS 10.0, and 10.0, 10.1 and 10.2
contain the same store.  The certificate store was last updated on
PAN-OS 11.0, and 11.0 and 11.1 contain the same store.

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
