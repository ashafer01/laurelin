# System

* Digital Ocean VPS with Debian 7.9
* OpenLDAP 2.4.31
* Cyrus SASL 2.1.25
* 389 Directory Server 1.3.6

# SASL

## SASL config ldif

```
dn: cn=config
changetype: modify
replace: olcAuthzRegexp
olcAuthzRegexp: uid=([^,]+),.* cn=$1,dc=example,dc=org
-
add: olcSaslAuxprops
olcSaslAuxprops: sasldb
-
add: olcSaslRealm
olcSaslRealm: example.org
-
add: olcSaslHost
olcSaslHost: example.org
-
```

## Adding sasl user password with

```
saslpasswd2 -u example.org -c $USER
```

## SASL auth control test case

```
% ldapwhoami -Y DIGEST-MD5 -U admin -H ldap://127.0.0.1
SASL/DIGEST-MD5 authentication started
Please enter your password: 
SASL username: admin
SASL SSF: 128
SASL data security layer installed.
dn:cn=admin,dc=example,dc=org
```

# LDAPS/StartTLS

* Certs set up following this [Stack Overflow answer](http://stackoverflow.com/a/21340898/94077)
* Configured OpenLDAP as follows:

```
dn: cn=config
changetype: modify
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /certs/serverkey.pem
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /certs/servercert.pem
-
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /certs/cacert.pem
```
* Added `ldaps://127.0.0.1:636` to `SLAPD_SERVICES` in `/etc/default/slapd`