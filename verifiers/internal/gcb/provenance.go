package gha

import (
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type gloudProvenance struct {
	ImageSummary struct {
		Digest              string `json:"digest"`
		FullQualifiedDigest string `json:"fully_qualified_digest"`
		Registry            string `json:"registry"`
		Repsitory           string `json:"repository"`
	} `json:"image_summary"`
	ProvenanceSummary struct {
		Provenance []struct{} `json:"provenance"`
	} `json:"provenance_summary"`
}

/*

 "kind": "BUILD",
        "name": "projects/gosst-scare-sandbox/occurrences/ffb703b9-354e-473d-90ab-5e1c86864243",
        "noteName": "projects/verified-builder/notes/intoto_62632e36-adac-4fc0-b384-bd212f167cab",
        "resourceUri": "https://us-west2-docker.pkg.dev/gosst-scare-sandbox/quickstart-docker-repo/quickstart-image@sha256:7f18ebaa2cd85412e28c5e0b35fba45db1d29476f30ec0897d59242605150aed",
        "updateTime": "2022-08-03T19:06:50.053076Z"

*/
// }
// 	"image_summary": {
// 	  "digest": "sha256:7f18ebaa2cd85412e28c5e0b35fba45db1d29476f30ec0897d59242605150aed",
// 	  "fully_qualified_digest": "us-west2-docker.pkg.dev/gosst-scare-sandbox/quickstart-docker-repo/quickstart-image@sha256:7f18ebaa2cd85412e28c5e0b35fba45db1d29476f30ec0897d59242605150aed",
// 	  "registry": "us-west2-docker.pkg.dev",
// 	  "repository": "quickstart-docker-repo"
// 	},
// 	"provenance_summary": {
// 	  "provenance": [
// 		{
// 		  "build": {

func EnvelopeFromBytes(payload []byte) (env *dsselib.Envelope, err error) {
	// env = &dsselib.Envelope{}
	// err = json.Unmarshal(payload, env)
	return
}
