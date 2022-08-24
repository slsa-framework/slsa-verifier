# Download the GCB keys

This is a temporary solution. We should try to automate key verification on pre-submits.
We should pin the CA certificate when downloading them, maybe using curl and the googlecloudapi REST endpoint.
See discussion in [#181](https://github.com/slsa-framework/slsa-verifier/issues/181).

For now, you can verify the keys we downloaded by downloading them yourself.

```shell
cd verifiers/internal/gcb/keys
gcloud compute regions list | grep -v NAME | xargs -0 | cut -d ' ' -f1 | xargs -i gcloud kms keys versions get-public-key 1 --location {} --keyring attestor --key builtByGCB --project verified-builder --output-file {}.key
```