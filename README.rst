pan-chainguard - Preload Trusted CA Intermediate Certificate Chains on PAN-OS
=============================================================================

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

Documentation
-------------

- Administrator's Guide:

  https://github.com/PaloAltoNetworks/pan-chainguard/blob/main/doc/admin-guide.rst

Install ``pan-chainguard``
--------------------------

``pan-chainguard`` is available as a
`release
<https://github.com/PaloAltoNetworks/pan-chainguard/releases/>`_
on GitHub and as a
`package
<https://pypi.org/project/pan-chainguard/>`_
on PyPi.
