# Major missing/incomplete features

The following features have not yet been implemented or are incomplete

* StartTLS
* Controls
* Extensions
* Extensible filters
* Binary data
* LDIF input
* Docs
* Possibly others - kindly open a ticket on github if you spot anything

# Walkthrough

Begin by initializing a connection to an LDAP server. Pass a URI string to the `LDAP` constructor:

```python
from laurelin.ldap import LDAP
ldap = LDAP('ldap://dir.example.org:389')
```

This will open a connection and query the server to find the "base DN" or DN suffix. With some server configurations, you may have to supply this yourself by passing the `baseDN` keyword argument, like so:

```python
ldap = LDAP('ldap://dir.example.org:389', baseDN='dc=example,dc=org')
```

An empty `LDAPObject` will be created with the base DN and stored as the `base` attribute on the `LDAP` instance. More on this later. For now we will briefly cover the basic LDAP interface which may seem somewhat familiar if you have used the standard python-ldap client before.

-----

**`LDAP.search()`** sends a search request and returns an iterable over instances of `LDAPObject`. Basic arguments are described here (listed in order):

* `baseDN` - the absolute DN to start the search from
* `scope` - One of:
  * `Scope.BASE` - only search `baseDN` itself
  * `Scope.ONE` - search `baseDN` and its immediate children
  * `Scope.SUB` - search `baseDN` and all of its descendents (default)
* `filter` - standard LDAP filter string
* `attrs` - a list of attributes to return for each object

Use **`LDAP.get()`** if you just need to get a single object by its DN. Also accepts an optional list of attributes.

-----

**`LDAP.add()`** adds a new object, and returns the corresponding `LDAPObject`, just pass the full, absolute DN and an [attributes dict](#attributes-dictionaries)

-----

**`LDAP.delete()`** deletes an entire object. Just pass the full, absolute DN of the object to delete.

-----

A python-ldap-style interface for specifying a complex atomic modify operation is provided, but it is discussed later. The following methods are preferred:

All accept the absolute DN of the object to modify, and an [attributes dictionary](#attributes-dictionaries).

**`LDAP.addAttrs()`** adds new attributes

**`LDAP.deleteAttrs()`** deletes attribute values. Pass an empty values list in the attributes dictionary to delete all values for an attribute.

**`LDAP.replaceAttrs()`** replaces all values for the given attributes with the values passed in the attributes dictionary. Atrributes that are not mentioned are not touched. Passing an empty list removes all values.

-----

Great, right? But specifying absolute DNs all the time is no fun. Enter `LDAPObject`, and keep in mind the `base` instance mentioned earlier.

`LDAPObject` inherits from `AttrsDict` to present attributes. This interface is documented [here](#attributes-dictionaries).

`LDAPObject` defines methods corresponding to all of the `LDAP` methods, but pass the object's `dn` automatically, or only require the RDN prefix, with the object's `dn` automatically appended to obtain the absolute DN.

**`LDAPObject.search()`** accepts all the same arguments as `LDAP.search()` except `baseDN` (and `scope` - more on this in future section). The object's own DN is always used for `baseDN`.

**`LDAPObject.getChild()`** is analagous to `LDAP.get()` but it only needs the RDN, appending the object's own DN as mentioned earlier. (Note that `LDAPObject.get()` inherits from the native `dict.get()`)

**`LDAPObject.addChild()`** is analagous to `LDAP.add()` again accepting an RDN in place of a full absolute DN.

Use **`LDAPObject.getAttr()`** like `dict.get()` except an empty list will always be returned as default if the attribute is not defined.

`LDAPObject`'s modify methods update the server first, then update the local attributes dictionary to match if successful. **`LDAPObject.addAttrs()`**, **`LDAPObject.deleteAttrs()`**, and **`LDAPObject.replaceAttrs()`** require only a new attributes dictionary as an argument, of the same format as for the matching `LDAP` methods.

```python
people = ldap.base.getChild('ou=people')

print(people['objectClass'])
# ['top', 'organizationalUnit']

people.addAttrs({'description':['Contains all users']})

# list all users
for user in people.search(filter='(objectClass=posixAccount)'):
    print(user['uid'][0])
```
This should cover the basics. More complexity to follow.

# Attributes Dictionaries
This common interface is used both for input and output of LDAP attributes. In short: dict keys are attribute names, and dict values are a `list` of attribute values. For example:

```python
{
    'objectClass': ['posixAccount', 'inetOrgPerson'],
    'uid': ['ashafer01'],
    'uidNumber': ['1000'],
    'gidNumber': ['100'],
    'cn': ['Alex Shafer'],
    'homeDirectory': ['/home/ashafer01'],
    'loginShell': ['/bin/zsh'],
    'mail': ['ashafer01@example.org'],
}
```
Note that there is an `AttrsDict` class defined in `laurelin.ldap.base`. There is **no requirement** to create instances of this class to pass as arguments, though you are welcome to if you find the additional methods on this class convenient. It provides methods like `getAttr()`, and local versions of all modify methods (used internally by online modify methods after success, e.g. `addAttrs_local()`). Further, it overrides `dict` special methods to enforce type requirements.

# Basic usage examples

## 1. Connect to local LDAP instance and iterate all objects

```python
from laurelin.ldap import LDAP

with LDAP('ldapi:///') as ldap:
    ldap.saslBind()
    for obj in ldap.base.search():
        print(obj.formatLDIF())
```

`saslBind()` defaults to the `EXTERNAL` mechanism when an `ldapi:` URI is given, which uses the current user for authorization via the unix socket (Known as "autobind" with 389 Directory Server)

