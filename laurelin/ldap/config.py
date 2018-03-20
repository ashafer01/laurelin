from .base import LDAP
from .constants import Scope
import six


def set_global_config(global_config_dict):
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
    conn_config_dict = config_dict['connection']
    start_tls = conn_config_dict.pop('start_tls', False)
    ldap = LDAP(**conn_config_dict)
    if start_tls:
        ldap.start_tls()
    for obj_config_dict in config_dict.get('objects', []):
        _create_single_object(ldap, obj_config_dict)
    return ldap


def create_object(ldap, config_dict):
    obj_config_dict = config_dict['object']
    _create_single_object(ldap, obj_config_dict)
