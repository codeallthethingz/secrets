# Secrets

Command line utility to generate and manage a JSON file that contains encrypted secrets and access lists to those secrets.

Uses AES with a passphrase to encrypt secrets.

The tool generates tokens for named services that have access to specific secrets.  Those tokens are also encrypted using the passphrase.

File format is read by a serverless app that can act as your secrets manager: https://github.com/codeallthethingz/secrets-service

## Installation

Check the project out in to your GO path and install.  Assumes GO home is also on your path.

```bash
git clone git@github.com:codeallthethingz/secrets
cd secrets
go install
```

## Usage

### adding a secret

```bash
> secrets -p "my super long passphrase" set "gcp-credentials" "base64 gcp json"
Creating: secrets.json
added secret
```

### adding access
```bash
> secrets -p "my super long passphrase" add-access "rpm.org" "gcp-credentials,mongo-token"
added access to rpm.org for gcp-credentials,mongo-token
Please use this token to access the secrets serice through the api
ea08dabb99f15e4573f16152397022455e04c161f9a047c2a5e1ede1a1f177f30b6af21991a10f73350e2d8c9c1b2611c0b37
```

