from .base import LDAP
from .constants import Scope
import six


def set_global_config(global_config_dict):
    """Set the global defaults. The dict must be formatted as follows::

        {'global': {
            <config param>: <config value>,
         }}

    ``<config param>`` must match one of the ``DEFAULT_`` attributes on :class:`.LDAP`. The ``DEFAULT_`` prefix is
    optional and dict keys are case-insensitive. Any parameters not specified will keep the hard-coded default.

    :param dict global_config_dict: See above.
    :rtype: None
    :raises KeyError: if the dict is incorrectly formatted or contains unknown config parameters
    """
    bad = []
    for key, val in six.iteritems(global_config_dict['global']):
        orig_key = key
        key = key.upper()
        if not key.startswith('DEFAULT_'):
            key = 'DEFAULT_'+key
        if hasattr(LDAP, key):
            setattr(LDAP, key, val)
        else:
            bad.append(orig_key)
    if bad:
        raise KeyError('Unknown global config keys: {0}'.format(', '.join(bad)))


def _create_single_object(ldap, obj_config_dict):
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

    For objects (optional):

    * If the ``dn`` parameter is specified, it is taken as an absolute DN.
    * You can specify the ``rdn`` parameter instead to create the object as a child of the connection's base object (the
      base of the tree).
    * The ``tag`` parameter is required; this is how created objects are accessed (:meth:`.LDAP.tag`).
    * Additional ``<object param>`` will be passed as keywords to :meth:`.LDAP.obj`.
    * If ``relative_search_scope`` is specified, use one of the strings `base`, `one`, or `sub`.
    * The server will not be queried to create these objects, so they will have no local attributes. Call
      :meth:`.LDAPObject.refresh` if you need to query attributes.

    :param config_dict: See above.
    :return: The new LDAP instance with any objects created and tagged.
    :raises TypeError: if any required object parameters are missing
    """
    conn_config_dict = config_dict['connection']
    start_tls = conn_config_dict.pop('start_tls', False)
    ldap = LDAP(**conn_config_dict)
    if start_tls:
        ldap.start_tls()
    for obj_config_dict in config_dict.get('objects', []):
        _create_single_object(ldap, obj_config_dict)
    return ldap
