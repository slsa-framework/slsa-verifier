package pkg

import (
	"encoding/json"
	"fmt"
)

/*
Envelope captures an envelope as described by the Secure Systems Lab
Signing Specification. See here:
https://github.com/secure-systems-lab/signing-spec/blob/master/envelope.md
*/
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

/*
Signature represents a generic in-toto signature that contains the identifier
of the key which was used to create the signature.
The used signature scheme has to be agreed upon by the signer and verifer
out of band.
The signature is a base64 encoding of the raw bytes from the signature
algorithm.
The cert is a PEM encoded string of the signing certificate
*/
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
	Cert  string `json:"cert"`
}

func GetCertFromEnvelope(signedAtt []byte) ([]byte, error) {
	// Unmarshal into an envelope.
	env := &Envelope{}
	if err := json.Unmarshal(signedAtt, env); err != nil {
		return nil, err
	}

	if len(env.Signatures) != 1 {
		return nil, fmt.Errorf("expected 1 signature on attestation")
	}

	return []byte(env.Signatures[0].Cert), nil
}
