package keys

// GoogleVSASigningPublicKey is the public key used to verify Google VSA signatures.
const GoogleVSASigningPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeGa6ZCZn0q6WpaUwJrSk+PPYEsca
3Xkk3UrxvbQtoZzTmq0zIYq+4QQl0YBedSyy+XcwAMaUWTouTrB05WhYtg==
-----END PUBLIC KEY-----`

// AttestorKeys is a map of Attestor IDs to their public keys.
var AttestorKeys = map[string]string{
	"keystore://76574:prod:vsa_signing_public_key": GoogleVSASigningPublicKey,
}
