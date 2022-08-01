# SLSA verifier as a service

This document is WIP.

Command to run the service locally:

```bash
$ docker build -f service/Dockerfile .
$ docker run -p 8000:8000 slsa-verifier-rest:latest # This did not work for me.
$ docker run --network=host slsa-verifier-rest:latest
```

```bash
$ curl -s 127.0.0.1:8000/v1/verify -d @./request.txt
```
