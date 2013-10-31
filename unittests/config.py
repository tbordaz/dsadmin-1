import logging
import lib389
from lib389 import DSAdmin
import fakeldap

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

DN_RMANAGER = 'uid=rmanager,cn=config'

auth = {'host': 'localhost',
        'port': 22389,
        'binddn': 'cn=directory manager',
        'bindpw': 'password'}


class MockDSAdmin(object):
    host = 'localhost'
    port = 22389
    sslport = 0

    def __str__(self):
        if self.sslport:
            return 'ldaps://%s:%s' % (self.host, self.sslport)
        else:
            return 'ldap://%s:%s' % (self.host, self.port)


def expect(entry, name, value):
    assert entry, "Bad entry %r " % entry
    assert entry.getValue(name) == value, "Bad value for entry %s. Expected %r vs %r" % (entry, entry.getValue(name), value)


def entry_equals(e1, e2):
    """compare using str()"""
    return str(e1) == str(e2)


def dfilter(my_dict, keys):
    """Filter a dict in a 2.4-compatible way"""
    return dict([(k, v) for k, v in my_dict.iteritems() if k in keys])


class MyMockLDDAP(fakeldap.MockLDAP):
    def __init__(self, *args, **kwds):
        kwds['directory'] = {
            'cn=directory manager': {
                    'cn': 'directory manager',
                    "userPassword": "password"
            },
            'cn=config': {
                'cn': 'config',
                'nsslapd-errorlog': '0',
                'nsslapd-instancedir': '/tmp/',
                'nsslapd-certdir' : '/tmp/',
                'nsslapd-schemadir' : '/tmp/',
                'nsslapd-errorlog-level' : '0',
                'nsslapd-accesslog-level' : '0',
            },
            'cn=plugins,cn=config': {
                'cn': 'plugins'
            },
            'cn=ldbm database,cn=plugins,cn=config': {
                'cn': 'ldbm database'
            }
            
        }
        fakeldap.MockLDAP.__init__(self, *args, **kwds)

DSAdmin.__bases__ = (MyMockLDDAP, )
