import ldap
import lib389
from lib389 import Entry
from tests.config import log

def harn_nolog(conn):
    """Speedup things disabiling logs"""
    conn.config.loglevel([lib389.LOG_DEFAULT])
    conn.config.loglevel([lib389.LOG_DEFAULT], level='access')

    
def drop_added_entries(conn):    
    while conn.added_entries:
        try:
            e = conn.added_entries.pop()
            log.info("removing entries %r" % conn.added_backends)
            conn.delete_s(e)
        except ldap.NOT_ALLOWED_ON_NONLEAF:
            log.error("Entry is not a leaf: %r" % e)
        except ldap.NO_SUCH_OBJECT:
            log.error("Cannot remove entry: %r" % e)

    log.info("removing backends %r" % conn.added_backends)
    for suffix in conn.added_backends:
        try:
            drop_backend(conn, suffix)
        except:
            log.exception("error removing %r" % suffix)
    for r in conn.added_replicas:
        try:
            drop_backend(conn, suffix=None, bename=r)
        except:
            log.exception("error removing %r" % r)


def drop_backend(conn, suffix, bename=None, maxnum=50):
    if not bename:
        bename = [x.dn for x in conn.getBackendsForSuffix(suffix)]
    
    if not bename:
        return None
        
    assert bename, "Missing bename for %r" % suffix
    if not hasattr(bename, '__iter__'):
        bename = [','.join(['cn=%s' % bename, lib389.DN_LDBM])]
    for be in bename:
        log.debug("removing entry from %r" % be)
        leaves = [x.dn for x in conn.search_s(
            be, ldap.SCOPE_SUBTREE, '(objectclass=*)', ['cn'])]
        # start deleting the leaves - which have the max number of ","
        leaves.sort(key=lambda x: x.count(","))
        while leaves and maxnum:
            # to avoid infinite loops
            # limit the iterations
            maxnum -= 1
            try:
                log.debug("removing %s" % leaves[-1])
                conn.delete_s(leaves[-1])
                leaves.pop()
            except:
                leaves.insert(0, leaves.pop())

        if not maxnum:
            raise Exception("BAD")


def addbackend_harn(conn, name, beattrs=None):
    """Create the suffix o=name and its backend."""
    suffix = "o=%s" % name
    e = Entry((suffix, {
               'objectclass': ['top', 'organization'],
               'o': [name]
               }))
    try:
        ret = conn.addSuffix(suffix, bename=name, beattrs=beattrs)
    except ldap.ALREADY_EXISTS:
        raise
    finally:
        conn.added_backends.add(suffix)

    conn.add_s(e)
    conn.added_entries.append(e.dn)
    
    return ret

