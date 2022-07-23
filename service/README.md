# SLSA verifier as a service

This document is WIP.

Command to run the serivce locally:

```bash
$ docker build -f service/Dockerfile .
$ docker run -p 8000:8000 slsa-verifier:latest # This did not work for me.
$ docker run --network=host slsa-verifier:latest
```

```bash
$ curl -s 127.0.0.1:8000/v1/verify -d @./request.txt
```
