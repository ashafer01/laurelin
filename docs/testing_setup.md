# System

Digital Ocean VPS with Debian 7.9
OpenLDAP 2.4.31
Cyrus SASL 2.1.25

## SASL config ldif

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

## Adding sasl user password with

    saslpasswd2 -u example.org -c $USER
