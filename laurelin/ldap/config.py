"""Provides support for establishing an LDAP connection and environment via config files and dicts"""


from .base import LDAP
from .constants import Scope, FilterSyntax
from .validation import Validator
import json
import six
import yaml
from importlib import import_module


def _default_mapper(val):
    return val


def _validator_mapper(val):
    instances = []
    for v in val:
        if isinstance(v, six.string_types):
            modname, objname = v.rsplit('.', 1)
            mod = import_module(modname)
            vcls = getattr(mod, objname)
            vobj = vcls()
            instances.append(vobj)
        elif isinstance(v, Validator):
            instances.append(v)
        else:
            raise TypeError('"validators" list must be str or laurelin.ldap.validation.Validator')
    return instances


_connection_mappers = {
    'validators': _validator_mapper,
    'default_filter_syntax': FilterSyntax.string,
}

_global_mappers = {
    'DEFAULT_FILTER_SYNTAX': FilterSyntax.string,
}


def normalize_global_config_param(key):
    """Normalize a global config key. Does not check validity of the key.

    :param str key: User-supplied global config key
    :return: The normalized key formatted as an attribute of :class:`.LDAP`
    :rtype: str
    """
    key = key.upper()
    if not key.startswith('DEFAULT_'):
        key = 'DEFAULT_'+key
    return key


def set_global_config(global_config_dict):
    """Set the global defaults. The dict must be formatted as follows::

        {'global': {
            <config param>: <config value>,
         }
        }

    ``<config param>`` must match one of the ``DEFAULT_`` attributes on :class:`.LDAP`. The ``DEFAULT_`` prefix is
    optional and dict keys are case-insensitive. Any parameters not specified will keep the hard-coded default.

    :param dict global_config_dict: See above.
    :rtype: None
    :raises KeyError: if the dict is incorrectly formatted or contains unknown config parameters
    """
    bad = []
    for key, val in six.iteritems(global_config_dict['global']):
        orig_key = key
        key = normalize_global_config_param(key)
        if hasattr(LDAP, key):
            val = _global_mappers.get(key, _default_mapper)(val)
            setattr(LDAP, key, val)
        else:
            bad.append(orig_key)
    if bad:
        raise KeyError('Unknown global config keys: {0}'.format(', '.join(bad)))


def activate_extensions(config_dict):
    """Activate the specified extensions. The dict must be formatted as follows::

        {'extensions': [
            <module name>,
         ]
        }

    :param dict config_dict: See above.
    :rtype: None
    """
    for mod_name in config_dict['extensions']:
        LDAP.activate_extension(mod_name)


def _create_single_object(ldap, obj_config_dict):
    if 'rdn' in obj_config_dict and 'dn' in obj_config_dict:
        raise TypeError('Choose only one of "rdn" or "dn"')
    if 'rdn' in obj_config_dict:
        objmeth = ldap.base.obj
    elif 'dn' in obj_config_dict:
        objmeth = ldap.obj
    else:
        raise TypeError('missing required object key "rdn" or "dn"')
    key = 'relative_search_scope'
    if key in obj_config_dict:
        obj_config_dict[key] = Scope.string(obj_config_dict[key])
    key = 'tag'
    if key not in obj_config_dict:
        raise TypeError('missing required object key "{0}"'.format(key))
    objmeth(**obj_config_dict)


def create_connection(config_dict):
    """Create a new connection from a config dict formatted as follows::

        {'connection': {
            'start_tls': <bool>,  # optional, default False
            'simple_bind': {  # optional, default no bind; mutually exclusive with sasl_bind
                'username': <string username or bind dn>,
                'password': <string password>
            },
            'sasl_bind': {  # optional, default no bind, mutually exclusive with simple_bind
                'mech': <standard mech name>,
                <mech prop>: <mech value>,  # required props varies by mech
            },
            <constructor param>: <constructor value>,
         },
         'objects': [  # optional
            {'dn': <object dn>,  # OR...
             'rdn': <dn relative to connection base object>,
             'tag': <unique tag name>,
             <object param>: <object value>,
            },
            # ...
         ]
        }

    ``<constructor param>`` must be one of the :class:`.LDAP` constructor keyword arguments.

    For ``validators`` you can optionally give the full path to the validator to use as a string, e.g.
    ``['laurelin.ldap.schema.SchemaValidator']``

    For ``default_filter_syntax`` give one of the strings "STANDARD" or "SIMPLE" (case-insensitive).

    For objects (optional):

    * If the ``dn`` parameter is specified, it is taken as an absolute DN.
    * You can specify the ``rdn`` parameter instead to create the object as a child of the connection's base object (the
      base of the tree).
    * The ``tag`` parameter is required; this is how created objects are accessed (:meth:`.LDAP.tag`).
    * Additional ``<object param>`` will be passed as keywords to :meth:`.LDAP.obj`.
    * If ``relative_search_scope`` is specified, use one of the strings `base`, `one`, or `sub`.
    * The server will not be queried to create these objects, so they will have no local attributes. Call
      :meth:`.LDAPObject.refresh` if you need to query attributes.

    Note on binding: You can always manually call :meth:`.LDAP.simple_bind` or :meth:`.LDAP.sasl_bind` on the
    :class:`.LDAP` instance returned from this method if statically configuring bind credentials is not desirable.

    :param config_dict: See above.
    :return: The new LDAP instance with any objects created and tagged.
    :raises TypeError: if any required object parameters are missing
    """
    conn_config_dict = config_dict['connection']
    start_tls = conn_config_dict.pop('start_tls', False)
    simple_bind = conn_config_dict.pop('simple_bind', False)
    sasl_bind = conn_config_dict.pop('sasl_bind', False)
    if simple_bind and sasl_bind:
        raise TypeError('choose only one of simple_bind or sasl_bind')
    for key in _connection_mappers:
        if key in conn_config_dict:
            val = _connection_mappers[key](conn_config_dict[key])
            conn_config_dict[key] = val
    ldap = LDAP(**conn_config_dict)
    if start_tls:
        ldap.start_tls()
    if simple_bind:
        ldap.simple_bind(**simple_bind)
    if sasl_bind:
        ldap.sasl_bind(**sasl_bind)
    for obj_config_dict in config_dict.get('objects', []):
        _create_single_object(ldap, obj_config_dict)
    return ldap


def load_file(path, file_decoder=None):
    """Load a config file. Must decode to dict with all components described on other methods as optional sections/keys.
    A YAML example::

        extensions:
          - laurelin.extensions.descattrs
          - laurelin.extensions.netgroups
        global:
          SSL_CA_PATH: /etc/ldap/cacerts
          IGNORE_EMPTY_LIST: true
        connection:
          server: ldap://dir01.example.org
          start_tls: true
          simple_bind:
            username: testuser
            passowrd: testpassword
          connect_timeout: 30
        objects:
          - rdn: ou=people
            tag: posix_user_base
          - rdn: ou=groups
            tag: posix_group_base
          - rdn: ou=netgroups
            tag: netgroup_base

    :param path: A path to a config file. Provides support for YAML and JSON format, or you can specify your own decoder
                 that returns a dict.
    :param file_decoder: A callable returning a dict when passed a file-like object
    :return: The LDAP connection if one was defined, None otherwise
    :rtype: LDAP or None
    :raises RuntimeError: if an unsupported file extension was given without the ``file_decoder`` argument.
    """
    if file_decoder is None:
        if path.endswith('.yml') or path.endswith('.yaml'):
            file_decoder = yaml.load
        elif path.endswith('.json'):
            file_decoder = json.load
        else:
            raise RuntimeError('Unsupported file type, must be YAML or JSON, or specify file_decoder argument')
    with open(path) as f:
        config_dict = file_decoder(f)
    return load_config_dict(config_dict)


def load_config_dict(config_dict):
    """Load config parameters from a dictionary. Must be formatted in the same was as ``load_file``

    :param dict config_dict: The config dictionary. See format in ``load_file``.
    :return: The LDAP connection if one was defined, None otherwise
    :rtype: LDAP or None
    """
    if 'global' in config_dict:
        set_global_config(config_dict)
    if 'extensions' in config_dict:
        activate_extensions(config_dict)
    if 'connection' in config_dict:
        return create_connection(config_dict)
