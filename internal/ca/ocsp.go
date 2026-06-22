package ca

import (
    "bytes"
    "crypto/sha1"
    "crypto/x509"
    "encoding/asn1"

    "golang.org/x/crypto/ocsp"
)

func getIssuerHashes(cert *x509.Certificate) ([]byte, []byte) {

    nameHash := sha1.Sum(cert.RawSubject)

    var pubKeyInfo struct {
        Algorithm        interface{}
        SubjectPublicKey asn1.BitString
    }

    _, _ = asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &pubKeyInfo)

    keyHash := sha1.Sum(pubKeyInfo.SubjectPublicKey.Bytes)

    return nameHash[:], keyHash[:]
}

func FindIssuer(req *ocsp.Request, cas []*CA) *CA {

    for _, ca := range cas {

        nameHash, keyHash := getIssuerHashes(ca.Cert)

        if bytes.Equal(nameHash, req.IssuerNameHash) &&
            bytes.Equal(keyHash, req.IssuerKeyHash) {

            return ca
        }
    }

    return nil
}
