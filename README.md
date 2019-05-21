# Secrets

[![Go Report Card](https://goreportcard.com/badge/github.com/codeallthethingz/secrets)](https://goreportcard.com/report/github.com/codeallthethingz/secrets)
[![codecov](https://codecov.io/gh/codeallthethingz/secrets/branch/master/graph/badge.svg)](https://codecov.io/gh/codeallthethingz/secrets)

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

### Help

```bash
[codeallthethingz:~]$ secrets help
NAME:
   secrets - json file-based secrets manager

USAGE:
   secrets [global options] command [command options] [arguments...]

VERSION:
   0.0.1

COMMANDS:
     set                set a secret to the credential file, overwrites if exists but keeps access list
     get                get a secret out of the secrets file
     list               list all the secrets in the credentials file
     remove             remove a secret from the credential file
     add-access         returns a new access token (or existing access token) with access to a comma separated secrets for a named service
     get-access-token   get access token for a service
     remove-access      remove access to the a comma separated list of secrets
     revoke-service     remove all access for a service and delete the service access token
     change-passphrase  change the passphrase to a new passphrase
     help, h            Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --passphrase value, -p value    the phrase to encrypt and decrypt the vault
   --secrets-file value, -f value  change the file that is being used to store secrets (default: "secrets.json")
   --help, -h                      show help
   --version, -v                   print the version
```
