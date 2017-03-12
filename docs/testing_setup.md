# System

* Digital Ocean VPS with Debian 7.9
* OpenLDAP 2.4.31
* Cyrus SASL 2.1.25
* 389 Directory Server 1.3.6

# SASL

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

## SASL auth control test case

    % ldapwhoami -Y DIGEST-MD5 -U admin -H ldap://127.0.0.1
    SASL/DIGEST-MD5 authentication started
    Please enter your password: 
    SASL username: admin
    SASL SSF: 128
    SASL data security layer installed.
    dn:cn=admin,dc=example,dc=org
