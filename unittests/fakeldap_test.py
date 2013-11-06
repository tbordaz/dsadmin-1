"""Test basic fakeldap usage, eg. if setup+teardown works

    GPL3 rpolli@babel.it
"""
from nose import *
from nose.tools import *

import config
from config import log
from config import *

import ldap
import time
import sys
import lib389
from lib389 import Entry
from lib389 import NoSuchEntryError
from lib389 import utils
from lib389.tools import DSAdminTools
from subprocess import Popen

from tests.harnesses import (harn_nolog, 
    drop_backend, 
    drop_added_entries,
    addbackend_harn)


conn = None
added_entries = None
added_backends = None


def setup():
    global conn
    conn = DSAdmin(**config.auth)
    conn.verbose = True
    conn.added_entries = []
    conn.added_backends = set()
    conn.added_replicas = []
    harn_nolog(conn)
    

def teardown():
    global conn
    conn.rebind()
    #drop_added_entries(conn)


#
# Tests
#



def setupBackend_ok_test():
    "setupBackend_ok calls brooker.Backend.add"
    try:
        be = conn.setupBackend('o=mockbe5', benamebase='mockbe5')
        assert be
    except ldap.ALREADY_EXISTS:
        raise
    finally:
        conn.added_backends.add('o=mockbe5')


@raises(ldap.ALREADY_EXISTS)
def setupBackend_double_test():
    "setupBackend_double calls brooker.Backend.add"
    be1 = conn.setupBackend('o=mockbe3', benamebase='mockbe3')
    conn.added_backends.add('o=mockbe3')
    be11 = conn.setupBackend('o=mockbe3', benamebase='mockbe3')

def get_backend_test():
    be = conn.getSuffixForBackend('mockbe3')    
    assert be, "Entry not found %r" % be
    

def addsuffix_test():
    addbackend_harn(conn, 'addressbook16')
    conn.added_backends.add('o=addressbook16')

