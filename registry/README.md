# Public key registry

Public key registry and merkle tree builder for OpenPassport.
We currently use the DSC list from the ICAO. The latest version can be downloaded [here](https://download.pkd.icao.int/). If you update them, be sure to change the filenames in the scripts!
As it does not contain all the DSCs used by all countries, we are working on verifying the full certificate chain up to CSCA, see [here](https://github.com/zk-passport/openpassport/issues/37).

Here is the certificate chain flow. Basically, CSCA certificates are used to sign DSC certificates which sign the SOD files contained in passport chips.

<p align="center">
  <img src="https://i.imgur.com/5h0S9Eh.jpeg" width="50%" height="50%">
</p>


More info are available on the [ICAO website](https://www.icao.int/Security/FAL/PKD/Pages/icao-master-list.aspx).

## Install dependencies

Install dependencies:
```
yarn install-registry
```

## Extract ICAO Masterlist

Extract the masterlist:
run the following command to extract the masterlist from the ICAO website as a folder of pem certificates.

| `$arg` | description | output |
| --- | --- | --- |
| `dsc` | extract the dsc masterlist | `outputs/dsc/pem_masterlist` |
| `csca` | extract the csca masterlist | `outputs/csca/pem_masterlist` |
| `all` | extract both

```bash
yarn extract-masterlist $arg
```

## Prisma
This repo is already setup to push the extracted masterlist to a postgres database.

### Setup
Add a .env file with the POSTGRES .env variables:
``` shell
POSTGRES_URL=""
POSTGRES_PRISMA_URL=""
POSTGRES_URL_NO_SSL=""
POSTGRES_URL_NON_POOLING=""
POSTGRES_USER=""
POSTGRES_HOST=""
POSTGRES_PASSWORD=""
POSTGRES_DATABASE=""
```
Init the database:
```bash
yarn db-init
```

### Push to database
Push the extracted masterlist to Postgres database:

| `$arg` | description |
| --- | --- |
| `dsc` | parse and push the dsc masterlist |
| `csca` | parse and push the csca masterlist |
| `all` | parse and push both

```bash
yarn db-push $arg
```

### JSON files

Build JSON files:
```
ts-node src/buildJson.ts
```
