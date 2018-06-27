OSG PKI Tools
=============

The Open Science Grid (OSG) Private Key Infrastructure (PKI) Tools provide a convenient command-line interface for
common X.509 certificate commands used by OSG site administrators.
Formerly, this repository contained a collection of tools to request, approve, renew, and revoke certificates from the
[OSG Certificate Authority (CA)](https://opensciencegrid.org/technology/policy/service-migrations-spring-2018/#osg-ca).
Currently, this repository only contains the `osg-cert-request` tool.

osg-cert-request
----------------

The `osg-cert-request` tool generates [certificate signing requests (CSRs)](https://en.wikipedia.org/wiki/Certificate_signing_request)
that can be submitted to CAs (e.g. InCommon) for the purpose of obtaining host certificates.

**Features:**

- Bulk generation of CSRs (and associated keys)
- Easy addition of Subject Alternative Names (SANs) to each CSR

### Synopsis ###

```
usage: osg-cert-request (-H HOSTNAME | -F HOSTFILE) -C COUNTRY -S STATE -L LOCALITY -O ORGANIZATION
                        [-h] [-a ALTNAMES] [-d WRITE_DIRECTORY] [-V]
```

### Options  ###

**Required options (specify only one of -H/--hostname and -F/--hostfile):**

| Option                 | Description                                                              |
|------------------------|--------------------------------------------------------------------------|
| `-H`, `--hostname`     | The hostname (FQDN) to request                                           |
| `-F`, `--hostfile`     | File containing list of hostnames (FQDN), one per line, to request.      |
|                        | Space separated SANs may be specified on the same line as each hostname. |
| `-C`, `--country`      | The 2-letter country code to associate with the generated CSR(s).        |
| `-S`, `--state`        | The unabbreviated state/province to associate with the generated CSR(s)  |
| `-L`, `--locality`     | The locality (i.e., city, town) to associate with the generated CSR(s)   |
| `-O`, `--organization` | The organization to associate with the generated CSR(s)                  |

**Optional options:**

| Option              | Description                                                                    |
|---------------------|--------------------------------------------------------------------------------|
| `-h`, `--help`      | Print the help message and exit                                                |
| `-a`, `--altname`   | Specify the SAN for the requested certificate (only works with -H/--hostname). |
|                     | May be specified more than once for additional SANs                            |
| `-d`, `--directory` | The directory to write the generated CSR(s) and host key(s)                    |
| `-V`, `--version`   | Show program's version number and exit                                         |
