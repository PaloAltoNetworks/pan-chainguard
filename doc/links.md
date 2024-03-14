# pan-chainguard Data and Process Flow

```mermaid
graph TD
    panos{{"PAN-OS NGFW, Panorama<br/>Export Default Trusted CAs"}}
    panos2{{"PAN-OS NGFW, Panorama<br/>Update Device Certificates"}}
    truststore[(trust-store.tgz)]
    truststoredir[(trust-store/)]
    fling(fling.py)
    chain(chain.py)
    guard(guard.py)
    curl(curl)
    untar(untar)
    fingerprints(cert-fingerprints.sh)
    fingerprintscsv[(cert-fingerprints.csv)]
    ccadb[("CCADB</br>All Certificate Information")]
    certificates[(certificates.tgz)]

    panos<-->|XML API|fling
    fling-->truststore
    truststore-->untar
    untar-->truststoredir
    truststoredir-->fingerprints
    fingerprints-->fingerprintscsv
    curl-->ccadb
    ccadb-->chain
    fingerprintscsv-->chain
    chain-->certificates
    certificates-->guard
    guard<-->|XML API|panos2
```
