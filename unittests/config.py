"""
    UnitTesting config.py

"""
from tests.config import *
import fakeldap

class MyMockLDDAP(fakeldap.MockLDAP):
    def set_empty_suffix(self, suffix):
        # Searching for missing backends should return an empty list
        self.set_return_value('search_s', 
            ('cn=plugins,cn=config', 
                ldap.SCOPE_SUBTREE, 
                '(&(objectclass=nsBackendInstance)(|(nsslapd-suffix={suffix})(nsslapd-suffix={suffix})))'.format(suffix=suffix), 
                'cn', 
                0),
            []
        )

    def __init__(self, *args, **kwds):
        kwds['directory'] = {
            'cn=directory manager': {
                    'cn': 'directory manager',
                    "userPassword": "password"
            },
            lib389.DN_CONFIG: {
                'cn': 'config',
                'nsslapd-errorlog': '0',
                'nsslapd-instancedir': '/tmp/',
                'nsslapd-certdir' : '/tmp/',
                'nsslapd-schemadir' : '/tmp/',
                'nsslapd-errorlog-level' : '0',
                'nsslapd-accesslog-level' : '0',
            },
            # This tree avoids NO_SUCH_ENTRY when searching on backends
            'cn=plugins,cn=config': {
                'cn': 'plugins'
            },
            'cn=ldbm database,cn=plugins,cn=config': {
                'cn': 'ldbm database'
            },
            lib389.DN_MAPPING_TREE : {
                'cn': 'mapping tree'            
            },
            'cn=config,cn=ldbm database,cn=plugins,cn=config': {
                'cn': 'config',
                'nsslapd-directory': '/tmp/foo'
            }
            
        }
        fakeldap.MockLDAP.__init__(self, *args, **kwds)

#
# monkeypatch the base class of DSAdmin
#
DSAdmin.__bases__ = (MyMockLDDAP, )
