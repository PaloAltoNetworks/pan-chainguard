pan-chainguard - Manage Root Store and Intermediate Certificate Chains on PAN-OS
================================================================================

Overview
--------

``pan-chainguard`` is a Python application which uses
`CCADB data
<https://www.ccadb.org/resources>`_
and allows PAN-OS SSL decryption administrators to:

#. Create a custom, up-to-date trusted root store for PAN-OS.
#. Determine intermediate certificate chains for trusted Certificate
   Authorities in PAN-OS so they can be `preloaded
   <https://wiki.mozilla.org/Security/CryptoEngineering/Intermediate_Preloading>`_
   as device certificates.

Issue 1: Out-of-date Root Store
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

Issue 2: Misconfigured Servers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pan-chainguard`` can create a custom root store, using one or more
of the major vendor root stores, which are managed by their CA
certificate program:

+ `Mozilla <https://wiki.mozilla.org/CA>`_
+ `Apple <https://www.apple.com/certificateauthority/ca_program.html>`_
+ `Chrome <https://g.co/chrome/root-policy>`_
+ `Microsoft <https://aka.ms/RootCert>`_

The custom root store can then be added to PAN-OS as trusted CA device
certificates.

Solution 2: Intermediate CA Preloading
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``pan-chainguard`` uses a root store and the
*All Certificate Information (root and intermediate) in CCADB (CSV)*
data file as input, and determines the intermediate certificate
chains, if available, for each root CA certificate.  These can then be
added to PAN-OS as trusted CA device certificates.

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
