
from nose import *

from dsadmin.utils import *
def normalizeDN_test():
    test = [ 
        (r'dc=example,dc=com', r'dc=example,dc=com'),
        (r'dc=example, dc=com', r'dc=example,dc=com'),
        (r'cn="dc=example,dc=com",cn=config', 'cn=dc\\=example\\,dc\\=com,cn=config'),
        ]
    for k,v in test:
        r = normalizeDN(k)
        assert r == v, "Mismatch %r vs %r" % (r,v)


def escapeDNValue_test():
    test = [ (r'"dc=example, dc=com"', r'\"dc\=example\,\ dc\=com\"') ]
    for k,v in test:
        r = escapeDNValue(k)
        assert r == v, "Mismatch %r vs %r" % (r,v)
        
def escapeDNFiltValue_test():
    test = [ (r'"dc=example, dc=com"', '\\22dc\\3dexample\\2c\\20dc\\3dcom\\22') ]
    for k,v in test:
        r = escapeDNFiltValue(k)
        assert r == v, "Mismatch %r vs %r" % (r,v)

import socket
def isLocalHost_test():
    test = [ 
        ('localhost', True), 
        ('localhost.localdomain', True),
        (socket.gethostname(), True),
        ('www.google.it', False) ]
    for k,v in test:
        r = isLocalHost(k)
        assert r == v, "Mismatch %r vs %r on %r" % (r,v, k)

    
