# pan-chainguard Data and Process Flow

```mermaid
graph TD
    panos{{"PAN-OS NGFW, Panorama<br/>Export Default Trusted CAs"}}
    panos2{{"PAN-OS NGFW, Panorama<br/>Update Device Certificates"}}
    truststore[(trust-store.tgz)]
    truststoredir[(trust-store/)]
    chain(chain.py)
    guard(guard.py)
    fling(fling.py)
    curl(curl)
    untar(untar)
    fingerprints(cert-fingerprints.sh)
    fingerprintscsv[(cert-fingerprints.csv)]
    ccadb[("CCADB</br>All Certificate Information")]
    certificates[(certificates.tgz)]

    panos<-->|XML API|chain
    untar-->truststoredir
    truststore-->untar
    chain-->truststore
    fingerprints-->fingerprintscsv
    curl-->ccadb
    ccadb-->guard
    fingerprintscsv-->guard
    truststoredir-->fingerprints
    guard-->certificates
    certificates-->fling
    fling<-->|XML API|panos2
```
