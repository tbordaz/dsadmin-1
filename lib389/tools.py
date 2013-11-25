"""Tools for creating and managing servers
    
    uses DSAdmin
"""
__all__ = ['DSAdminTools']
try:
    from subprocess import Popen, PIPE, STDOUT
    HASPOPEN = True
except ImportError:
    import popen2
    HASPOPEN = False

import sys
import os, re
import os.path
import base64
import urllib
import urllib2
import ldap
import operator
import select
import time
import shutil
import subprocess
import tarfile
import re
import glob

import lib389
from lib389 import InvalidArgumentError, NoSuchEntryError, DN_CONFIG, DN_LDBM

from lib389.utils import (
    getcfgdsuserdn, 
    getcfgdsinfo, 
    getcfgdsuserdn, 
    update_newhost_with_fqdn,
    get_sbin_dir, get_server_user, getdomainname,
    isLocalHost, formatInfData, getserverroot,
    
    update_admin_domain,getadminport,getdefaultsuffix,
    
    )
from lib389._ldifconn import LDIFConn
from lib389._constants import DN_DM

import logging
logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

# Private constants
PATH_SETUP_DS_ADMIN = "/setup-ds-admin.pl"
PATH_SETUP_DS = "/setup-ds.pl"
PATH_REMOVE_DS = "/remove-ds.pl"
PATH_ADM_CONF = "/etc/dirsrv/admin-serv/adm.conf"

class DSAdminTools(object):
    """DSAdmin mix-in."""

    @staticmethod
    def initialize_dsadmin_for_tools(self):
        """Initialize the DSAdmin structure filling various fields, like:
            - dbdir
            - errlog
            - confdir

        """
        if self.binddn and len(self.binddn) and not hasattr(self, 'sroot'):
            try:
                # XXX this fields are stale and not continuously updated
                # do they have sense?
                ent = self.getEntry(DN_CONFIG, attrlist=[
                    'nsslapd-instancedir', 
                    'nsslapd-errorlog',
                    'nsslapd-certdir', 
                    'nsslapd-schemadir'])
                self.errlog = ent.getValue('nsslapd-errorlog')
                self.confdir = ent.getValue('nsslapd-certdir')
                
                if self.isLocal:
                    if not self.confdir or not os.access(self.confdir + '/dse.ldif', os.R_OK):
                        self.confdir = ent.getValue('nsslapd-schemadir')
                        if self.confdir:
                            self.confdir = os.path.dirname(self.confdir)
                instdir = ent.getValue('nsslapd-instancedir')
                if not instdir and self.isLocal:
                    # get instance name from errorlog
                    # move re outside
                    self.inst = re.match(
                        r'(.*)[\/]slapd-([^/]+)/errors', self.errlog).group(2)
                    if self.isLocal and self.confdir:
                        instdir = self.getDseAttr('nsslapd-instancedir')
                    else:
                        instdir = re.match(r'(.*/slapd-.*)/logs/errors',
                                           self.errlog).group(1)
                if not instdir:
                    instdir = self.confdir
                if self.verbose:
                    log.debug("instdir=%r" % instdir)
                    log.debug("Entry: %r" % ent)
                match = re.match(r'(.*)[\/]slapd-([^/]+)$', instdir)
                if match:
                    self.sroot, self.inst = match.groups()
                else:
                    self.sroot = self.inst = ''
                ent = self.getEntry('cn=config,' + DN_LDBM,
                    attrlist=['nsslapd-directory'])
                self.dbdir = os.path.dirname(ent.getValue('nsslapd-directory'))
            except (ldap.INSUFFICIENT_ACCESS, ldap.CONNECT_ERROR, NoSuchEntryError):
                log.exception("Skipping exception during initialization")
            except ldap.OPERATIONS_ERROR, e:
                log.exception("Skipping exception: Probably Active Directory")
            except ldap.LDAPError, e:
                log.exception("Error during initialization")
                raise


    @staticmethod
    def cgiFake(sroot, verbose, prog, args):
        """Run the local program prog as a CGI using the POST method."""
        content = urllib.urlencode(args)
        length = len(content)
        # setup CGI environment
        env = os.environ.copy()
        env['REQUEST_METHOD'] = "POST"
        env['NETSITE_ROOT'] = sroot
        env['CONTENT_LENGTH'] = str(length)
        progdir = os.path.dirname(prog)
        if HASPOPEN:
            pipe = Popen(prog, cwd=progdir, env=env,
                         stdin=PIPE, stdout=PIPE, stderr=STDOUT)
            child_stdin = pipe.stdin
            child_stdout = pipe.stdout
        else:
            saveenv = os.environ
            os.environ = env
            child_stdout, child_stdin = popen2.popen2(prog)
            os.environ = saveenv
        child_stdin.write(content)
        child_stdin.close()
        for line in child_stdout:
            if verbose:
                sys.stdout.write(line)
            ary = line.split(":")
            if len(ary) > 1 and ary[0] == 'NMC_Status':
                exitCode = ary[1].strip()
                break
        child_stdout.close()
        if HASPOPEN:
            osCode = pipe.wait()
            print "%s returned NMC code %s and OS code %s" % (
                prog, exitCode, osCode)
        return exitCode

    @staticmethod
    def cgiPost(host, port, username, password, uri, verbose, secure, args=None):
        """Post the request to the admin server.

           Admin server requires authentication, so we use the auth handler classes.

            NOTE: the url classes in python use the deprecated
            base64.encodestring() function, which truncates lines,
            causing Apache to give us a 400 Bad Request error for the
            Authentication string.  So, we have to tell
            base64.encodestring() not to truncate."""
        args = args or {}
        prefix = 'http'
        if secure:
            prefix = 'https'
        hostport = host + ":" + port
        # construct our url
        url = '%s://%s:%s%s' % (prefix, host, port, uri)
        # tell base64 not to truncate lines
        savedbinsize = base64.MAXBINSIZE
        base64.MAXBINSIZE = 256
        # create the password manager - we don't care about the realm
        passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
        # add our password
        passman.add_password(None, hostport, username, password)
        # create the auth handler
        authhandler = urllib2.HTTPBasicAuthHandler(passman)
        # create our url opener that handles basic auth
        opener = urllib2.build_opener(authhandler)
        # make admin server think we are the console
        opener.addheaders = [('User-Agent', 'Fedora-Console/1.0')]
        if verbose:
            print "requesting url", url
            sys.stdout.flush()
        exitCode = 1
        try:
            req = opener.open(url, urllib.urlencode(args))
            for line in req:
                if verbose:
                    print line
                ary = line.split(":")
                if len(ary) > 1 and ary[0] == 'NMC_Status':
                    exitCode = ary[1].strip()
                    break
            req.close()
#         except IOError, e:
#             print e
#             print e.code
#             print e.headers
#             raise
        finally:
            # restore binsize
            base64.MAXBINSIZE = savedbinsize
        return exitCode

    @staticmethod
    def serverCmd(self, cmd, verbose, timeout=120):
        """NOTE: this tries to open the log!
        """
        instanceDir = os.path.join(self.sroot, "slapd-" + self.inst)

        errLog = instanceDir + '/logs/errors'
        if hasattr(self, 'errlog'):
            errLog = self.errlog
        done = False
        started = True
        lastLine = ""
        cmd = cmd.lower()
        fullCmd = instanceDir + "/" + cmd + "-slapd"
        if cmd == 'start':
            cmdPat = 'slapd started.'
        else:
            cmdPat = 'slapd stopped.'

        if "USE_GDB" in os.environ or "USE_VALGRIND" in os.environ:
            timeout = timeout * 3
        timeout += int(time.time())
        if cmd == 'stop':
            log.warn("unbinding before stop")
            try:
                self.unbind()
            except:
                log.warn("Unbinding fails: Instance already down (stopped or killed) ?")
                pass

        log.info("Setup error log")
        logfp = open(errLog, 'r')
        logfp.seek(0, os.SEEK_END)  # seek to end
        pos = logfp.tell()  # get current position
        logfp.seek(pos, os.SEEK_SET)  # reset the EOF flag

        log.warn("Running command: %r" % fullCmd)
        rc = os.system(fullCmd)
        while not done and int(time.time()) < timeout:
            line = logfp.readline()
            while not done and line:
                lastLine = line
                if verbose:
                    log.debug("current line: %r" % line.strip())
                if line.find(cmdPat) >= 0:
                    started += 1
                    if started == 2:
                        done = True
                elif line.find("Initialization Failed") >= 0:
                    # sometimes the server fails to start - try again
                    rc = os.system(fullCmd)
                elif line.find("exiting.") >= 0:
                    # possible transient condition - try again
                    rc = os.system(fullCmd)
                pos = logfp.tell()
                line = logfp.readline()
            if line.find("PR_Bind") >= 0:
                # server port conflicts with another one, just report and punt
                log.debug("last line: %r" % lastLine.strip())
                log.warn("This server cannot be started until the other server on this port is shutdown")
                done = True
            if not done:
                time.sleep(2)
                logfp.seek(pos, 0)
        logfp.close()
        if started < 2:
            now = int(time.time())
            if now > timeout:
                log.warn(
                    "Probable timeout: timeout=%d now=%d" % (timeout, now))

            log.error("Error: could not %s server %s %s: %d" % (
                      cmd, self.sroot, self.inst, rc))
            return 1
        else:
            log.info("%s was successful for %s %s" % (
                     cmd, self.sroot, self.inst))
            if cmd == 'start':
                self.__localinit__()
        return 0

    @staticmethod
    def stop(self, verbose=False, timeout=0):
        """Stop server or raise."""
        DSAdminTools.initialize_dsadmin_for_tools(self)
        if not self.isLocal and hasattr(self, 'asport'):
            log.info("stopping remote server ", self)
            self.unbind()
            log.info("closed remote server ", self)
            cgiargs = {}
            rc = DSAdminTools.cgiPost(self.host, self.asport, self.cfgdsuser,
                                      self.cfgdspwd,
                                      "/slapd-%s/Tasks/Operation/stop" % self.inst,
                                      verbose, cgiargs)
            log.info("stopped remote server %s rc = %d" % (self, rc))
            return rc
        else:
            return DSAdminTools.serverCmd(self, 'stop', verbose, timeout)

    @staticmethod
    def start(self, verbose=False, timeout=0):
        DSAdminTools.initialize_dsadmin_for_tools(self)

        if not self.isLocal and hasattr(self, 'asport'):
            log.debug("starting remote server %s " % self)
            cgiargs = {}
            rc = DSAdminTools.cgiPost(self.host, self.asport, self.cfgdsuser,
                                      self.cfgdspwd,
                                      "/slapd-%s/Tasks/Operation/start" % self.inst,
                                      verbose, cgiargs)
            log.debug("connecting remote server %s" % self)
            if not rc:
                self.__localinit__()
            log.info("started remote server %s rc = %d" % (self, rc))
            return rc
        else:
            log.debug("Starting server %r" % self)
            return DSAdminTools.serverCmd(self, 'start', verbose, timeout)
        
    @staticmethod
    def _infoInstanceBackupFS(dsadmin):
        """
            Return the information to retrieve the backup file of a given instance
            It returns:
                - Directory name containing the backup (e.g. /tmp/slapd-standalone.bck)
                - The pattern of the backup files (e.g. /tmp/slapd-standalone.bck/backup*.tar.gz)
        """
        backup_dir = "%s/slapd-%s.bck" % (dsadmin.backupdir, dsadmin.inst)     
        backup_pattern = os.path.join(backup_dir, "backup*.tar.gz") 
        return backup_dir, backup_pattern
    
    @staticmethod
    def clearInstanceBackupFS(dsadmin=None, backup_file=None):
        """
            Remove a backup_file or all backup up of a given instance
        """
        if backup_file:
            if os.path.isfile(backup_file):
                try:
                    os.remove(backup_file)
                except:
                    log.info("clearInstanceBackupFS: fail to remove %s" % backup_file)
                    pass
        elif dsadmin:
            backup_dir, backup_pattern = DSAdminTools._infoInstanceBackupFS(dsadmin)
            list_backup_files = glob.glob(backup_pattern)
            for f in list_backup_files:
                try:
                    os.remove(f)
                except:
                    log.info("clearInstanceBackupFS: fail to remove %s" % backup_file)
                    pass

    @staticmethod
    def checkInstanceBackupFS(dsadmin):
        """
            If it exits a backup file, it returns it
            else it returns None
        """

        backup_dir, backup_pattern = DSAdminTools._infoInstanceBackupFS(dsadmin)
        list_backup_files = glob.glob(backup_pattern)
        if not list_backup_files:
            return None
        else:
            # returns the first found backup
            return list_backup_files[0]

        
    @staticmethod
    def instanceBackupFS(dsadmin):
        """
            Saves the files of an instance under /tmp/slapd-<instance_name>.bck/backup_HHMMSS.tar.gz
            and return the archive file name.
            If it already exists a such file, it assums it is a valid backup and 
            returns its name
            
            dsadmin.sroot : root of the instance  (e.g. /usr/lib64/dirsrv)
            dsadmin.inst  : instance name (e.g. standalone for /etc/dirsrv/slapd-standalone)
            dsadmin.confdir : root of the instance config (e.g. /etc/dirsrv)
            dsadmin.dbdir: directory where is stored the database (e.g. /var/lib/dirsrv/slapd-standalone/db)
            dsadmin.changelogdir: directory where is stored the changelog (e.g. /var/lib/dirsrv/slapd-master/changelogdb)
        """
        
        # First check it if already exists a backup file
        backup_dir, backup_pattern = DSAdminTools._infoInstanceBackupFS(dsadmin)
        backup_file = DSAdminTools.checkInstanceBackupFS(dsadmin)
        if backup_file is None:
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
        else:
            return backup_file
                
        # goes under the directory where the DS is deployed
        listFilesToBackup = []
        here = os.getcwd()
        os.chdir(dsadmin.prefix)
        prefix_pattern = "%s/" % dsadmin.prefix
        
        # build the list of directories to scan
        instroot = "%s/slapd-%s" % (dsadmin.sroot, dsadmin.inst)
        ldir = [ instroot ]
        if hasattr(dsadmin, 'confdir'):
            ldir.append(dsadmin.confdir)
        if hasattr(dsadmin, 'dbdir'):
            ldir.append(dsadmin.dbdir)
        if hasattr(dsadmin, 'changelogdir'):
            ldir.append(dsadmin.changelogdir)
        if hasattr(dsadmin, 'errlog'):
            ldir.append(os.path.dirname(dsadmin.errlog))
        if hasattr(dsadmin, 'accesslog') and  os.path.dirname(dsadmin.accesslog) not in ldir:
            ldir.append(os.path.dirname(dsadmin.accesslog))        

        # now scan the directory list to find the files to backup
        for dirToBackup in ldir:
            for root, dirs, files in os.walk(dirToBackup):
                for file in files:
                    name = os.path.join(root, file)
                    name = re.sub(prefix_pattern, '', name)

                    if os.path.isfile(name):
                        listFilesToBackup.append(name)
                        log.debug("instanceBackupFS add = %s (%s)" % (name, dsadmin.prefix))
                
        
        # create the archive
        name = "backup_%s.tar.gz" % (time.strftime("%m%d%Y_%H%M%S"))
        backup_file = os.path.join(backup_dir, name)
        tar = tarfile.open(backup_file, "w:gz")

        
        for name in listFilesToBackup:
            if os.path.isfile(name):
                tar.add(name)
        tar.close()
        log.info("instanceBackupFS: archive done : %s" % backup_file)
        
        # return to the directory where we were
        os.chdir(here)
        
        return backup_file

    @staticmethod
    def instanceRestoreFS(dsadmin, backup_file):
        """
        """
        
        # First check the archive exists
        if backup_file is None:
            log.warning("Unable to restore the instance (missing backup)")
            return 1
        if not os.path.isfile(backup_file):
            log.warning("Unable to restore the instance (%s is not a file)" % backup_file)
            return 1
        
        #
        # Second do some clean up 
        #
        
        # previous db (it may exists new db files not in the backup)
        log.debug("instanceRestoreFS: remove subtree %s/*" % dsadmin.dbdir)
        for root, dirs, files in os.walk(dsadmin.dbdir):
            for d in dirs:
                if d not in ("bak", "ldif"):
                    log.debug("instanceRestoreFS: before restore remove directory %s/%s" % (root, d))
                    shutil.rmtree("%s/%s" % (root, d))
        
        # previous error/access logs
        log.debug("instanceRestoreFS: remove error logs %s" % dsadmin.errlog)
        for f in glob.glob("%s*" % dsadmin.errlog):
                log.debug("instanceRestoreFS: before restore remove file %s" % (f))
                os.remove(f)
        log.debug("instanceRestoreFS: remove access logs %s" % dsadmin.accesslog)
        for f in glob.glob("%s*" % dsadmin.accesslog):
                log.debug("instanceRestoreFS: before restore remove file %s" % (f))
                os.remove(f)
        
        
        # Then restore from the directory where DS was deployed
        here = os.getcwd()
        os.chdir(dsadmin.prefix)
        
        tar = tarfile.open(backup_file)
        for member in tar.getmembers():
            if os.path.isfile(member.name):
                #
                # restore only writable files
                # It could be a bad idea and preferably restore all.
                # Now it will be easy to enhance that function.
                if os.access(member.name, os.W_OK):
                    log.debug("instanceRestoreFS: restored %s" % member.name)
                    tar.extract(member.name)
                else:
                    log.debug("instanceRestoreFS: not restored %s (no write access)" % member.name)
            else:
                log.debug("instanceRestoreFS: restored %s" % member.name)
                tar.extract(member.name)
            
        tar.close()
        
        #
        # Now be safe, triggers a recovery at restart
        #
        guardian_file = os.path.join(dsadmin.dbdir, "db/guardian")
        if os.path.isfile(guardian_file):
            try:
                log.debug("instanceRestoreFS: remove %s" % guardian_file)
                os.remove(guardian_file)
            except:
                log.warning("instanceRestoreFS: fail to remove %s" % guardian_file)
                pass
        
        
        os.chdir(here)
        
    @staticmethod
    def setupSSL(dsadmin, secport=636, sourcedir=None, secargs=None):
        """configure and setup SSL with a given certificate and restart the server.
        
            See DSAdmin.configSSL for the secargs values
        """
        DSAdminTools.initialize_dsadmin_for_tools(dsadmin)
        e = dsadmin.configSSL(secport, secargs)
        log.info("entry is %r" % [e])
        dn_config = e.dn
        # get our cert dir
        e_config = dsadmin.getEntry(
            dn_config, ldap.SCOPE_BASE, '(objectclass=*)')
        certdir = e_config.getValue('nsslapd-certdir')
        # have to stop the server before replacing any security files
        DSAdminTools.stop(dsadmin)
        # allow secport for selinux
        if secport != 636:
            log.debug("Configuring SELinux on port:", secport)
            cmd = 'semanage port -a -t ldap_port_t -p tcp %s' % secport
            os.system(cmd)

        # eventually copy security files from source dir to our cert dir
        if sourcedir:            
            for ff in ['cert8.db', 'key3.db', 'secmod.db', 'pin.txt', 'certmap.conf']:
                srcf = os.path.join(sourcedir, ff)
                destf = os.path.join(certdir, ff)
                # make sure dest is writable so we can copy over it
                try:
                    log.info("Copying security files: %s to %s" % (srcf, destf))
                    mode = os.stat(destf).st_mode
                    newmode = mode | 0600
                    os.chmod(destf, newmode)
                except Exception, e:
                    print e
                    pass  # oh well
                # copy2 will copy the mode too
                shutil.copy2(srcf, destf)

        # now, restart the ds
        DSAdminTools.start(dsadmin, True)

    @staticmethod
    def runInfProg(prog, content, verbose):
        """run a program that takes an .inf style file on stdin"""
        cmd = [ '/usr/bin/sudo' ]
        cmd.append('/usr/bin/perl')
        cmd.append( prog )
        #cmd = [prog]
        if verbose:
            cmd.append('-ddd')
        else:
            cmd.extend(['-l', '/dev/null'])
        cmd.extend(['-s', '-f', '-'])
        print "running: %s " % cmd
        if HASPOPEN:
            pipe = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
            child_stdin = pipe.stdin
            child_stdout = pipe.stdout
        else:
            pipe = popen2.Popen4(cmd)
            child_stdin = pipe.tochild
            child_stdout = pipe.fromchild
        child_stdin.write(content)
        child_stdin.close()
        while not pipe.poll():
            (rr, wr, xr) = select.select([child_stdout], [], [], 1.0)
            if rr and len(rr) > 0:
                line = rr[0].readline()
                if not line:
                    break
                if verbose:
                    sys.stdout.write(line)
            elif verbose:
                print "timed out waiting to read from", cmd
        child_stdout.close()
        exitCode = pipe.wait()
        if verbose:
            print "%s returned exit code %s" % (prog, exitCode)
        return exitCode

    @staticmethod
    def removeInstance(instance):
        """run the remove instance command"""
        cmd = "/usr/bin/sudo /usr/bin/perl /usr/sbin/remove-ds.pl -i slapd-%s" % instance
        #print "running: %s " % cmd
        try:
            os.system(cmd)
        except:
            log.exception("error executing %r" % cmd)
            
    @staticmethod
    def _offlineDSAdmin(args):
        '''
            Function to allocate an offline DSAdmin instance.
            This instance is not initialized with the Directory instance
            (__localinit__() and __add_brookers__() are not called)
            The properties set are:
                instance.host
                instance.port
                instance.serverId
                instance.inst
                instance.prefix
                instance.backup
        '''
        instance = lib389.DSAdmin(host=args['newhost'], port=args['newport'], 
                                 serverId=args['newinstance'], offline=True)
        instance.prefix    = args.get('prefix', '/')
        instance.backupdir = args.get('backupdir', '/tmp')
        instance.inst      = instance.serverId
        return instance
            
    @staticmethod
    def existsBackup(args):
        '''
            If the backup of the instance exists, it returns it.
            Else None
        '''
        instance = DSAdminTools._offlineDSadmin(args)
        return DSAdminTools.checkInstanceBackupFS(instance)
        
  
    @staticmethod
    def existsInstance(args):
        '''
            Check if an instance exists.
            It checks if the following directories/files exist:
                <confdir>/slapd-<name>
                <errlog>         
            If it exists it returns a DSAdmin instance NOT initialized, else None
        '''
        instance = DSAdminTools._offlineDSAdmin(args)
        dirname  = os.path.join(instance.prefix, "etc/dirsrv/slapd-%s" % instance.serverId)
        errorlog = os.path.join(instance.prefix, "var/log/dirsrv/slapd-%s/errors" % instance.serverId)
        sroot    = os.path.join(instance.prefix, "lib/dirsrv")
        if  os.path.isdir(dirname) and \
            os.path.isfile(errorlog) and \
            os.path.isdir(sroot):
            instance.sroot = sroot
            instance.errlog = errorlog
            return instance
        
        return None

    @staticmethod
    def createInstance(args, verbose=0):
        """Create a new instance of directory server and return a connection to it.

        This function:
        - guesses the hostname where to create the DS, using
        localhost by default;
        - figures out if the given hostname is the local host or not.
        
        @param args -  a dict with the following values {
            # new instance compulsory values
            'newinstance': 'rpolli',
            'newsuffix': 'dc=example,dc=com',            
            'newhost': 'localhost.localdomain',
            'newport': 22389,
            'newrootpw': 'password',            
            
            # optionally register instance on an admin tree
            'have_admin': True,
            
            # optionally directory where to store instance backup
            'backupdir': [ /tmp ]
            
            # you can configure a new dirsrv-admin
            'setup_admin': True,
            
            # or you need the dirsrv-admin to be already setup
            'cfgdshost': 'localhost.localdomain',
            'cfgdsport': 22389,
            'cfgdsuser': 'admin',
            'cfgdspwd': 'admin',
        
        }        
        """
        cfgdn = lib389.CFGSUFFIX
        isLocal = update_newhost_with_fqdn(args)
        
        # use prefix if binaries are relocated
        sroot = args.get('sroot', '')
        prefix = args.setdefault('prefix', '')
        
        # get the backup directory to store instance backup
        backupdir = args.get('backupdir', '/tmp')

        # new style - prefix or FHS?
        args['new_style'] = not args.get('sroot')

        # do we have ds only or ds+admin?
        if 'no_admin' not in args:
            sbindir = get_sbin_dir(sroot, prefix)
            if os.path.isfile(sbindir + PATH_SETUP_DS_ADMIN):
                args['have_admin'] = True

        # set default values
        args['have_admin'] = args.get('have_admin', False)
        args['setup_admin'] = args.get('setup_admin', False)

        # get default values from adm.conf
        if args['new_style'] and args['have_admin']:
            admconf = LDIFConn(
                args['prefix'] + PATH_ADM_CONF)
            args['admconf'] = admconf.get('')

        # next, get the configuration ds host and port
        if args['have_admin']:
            args['cfgdshost'], args['cfgdsport'], cfgdn = getcfgdsinfo(args)
        #
        # if a Config DS is passed, get the userdn. This creates
        # a connection to the given DS. If you don't want to connect
        # to this server you should pass 'setup_admin' too.
        #
        if args['have_admin'] and not args['setup_admin']:
            cfgconn = getcfgdsuserdn(cfgdn, args)
            
        # next, get the server root if not given
        if not args['new_style']:
            getserverroot(cfgconn, isLocal, args)
        # next, get the admin domain
        if args['have_admin']:
            update_admin_domain(isLocal, args)
        # next, get the admin server port and any other information - close the cfgconn
        if args['have_admin'] and not args['setup_admin']:
            asport, secure = getadminport(cfgconn, cfgdn, args)
        # next, get the posix username
        get_server_user(args)
        # fixup and verify other args
        args['newport'] = args.get('newport', 389)
        args['newrootdn'] = args.get('newrootdn', DN_DM)
        args['newsuffix'] = args.get('newsuffix', getdefaultsuffix(args['newhost']))
            
        if not isLocal or 'cfgdshost' in args:
            if 'admin_domain' not in args:
                args['admin_domain'] = getdomainname(args['newhost'])
            if isLocal and 'cfgdspwd' not in args:
                args['cfgdspwd'] = "dummy"
            if isLocal and 'cfgdshost' not in args:
                args['cfgdshost'] = args['newhost']
            if isLocal and 'cfgdsport' not in args:
                args['cfgdsport'] = 55555
        missing = False
        for param in ('newhost', 'newport', 'newrootdn', 'newrootpw', 'newinstance', 'newsuffix'):
            if param not in args:
                log.error("missing required argument: ", param)
                missing = True
        if missing:
            raise InvalidArgumentError("missing required arguments")

        # try to connect with the given parameters
        try:
            newconn = lib389.DSAdmin(args['newhost'], args['newport'],
                              args['newrootdn'], args['newrootpw'], args['newinstance'])
            newconn.prefix = prefix
            newconn.backupdir = backupdir
            newconn.isLocal = isLocal
            if args['have_admin'] and not args['setup_admin']:
                newconn.asport = asport
                newconn.cfgdsuser = args['cfgdsuser']
                newconn.cfgdspwd = args['cfgdspwd']
            print "Warning: server at %s:%s already exists, returning connection to it" % \
                  (args['newhost'], args['newport'])
            return newconn
        except ldap.SERVER_DOWN:
            pass  # not running - create new one

        if not isLocal or 'cfgdshost' in args:
            for param in ('cfgdshost', 'cfgdsport', 'cfgdsuser', 'cfgdspwd', 'admin_domain'):
                if param not in args:
                    print "missing required argument", param
                    missing = True
        if not isLocal and not asport:
            print "missing required argument admin server port"
            missing = True
        if missing:
            raise InvalidArgumentError("missing required arguments")

        # construct a hash table with our CGI arguments - used with cgiPost
        # and cgiFake
        cgiargs = {
            'servname': args['newhost'],
            'servport': args['newport'],
            'rootdn': args['newrootdn'],
            'rootpw': args['newrootpw'],
            'servid': args['newinstance'],
            'suffix': args['newsuffix'],
            'servuser': args['newuserid'],
            'start_server': 1
        }
        if 'cfgdshost' in args:
            cgiargs['cfg_sspt_uid'] = args['cfgdsuser']
            cgiargs['cfg_sspt_uid_pw'] = args['cfgdspwd']
            cgiargs['ldap_url'] = "ldap://%s:%d/%s" % (
                args['cfgdshost'], args['cfgdsport'], cfgdn)
            cgiargs['admin_domain'] = args['admin_domain']

        if not isLocal:
            DSAdminTools.cgiPost(args['newhost'], asport, args['cfgdsuser'],
                                 args['cfgdspwd'], "/slapd/Tasks/Operation/Create", verbose,
                                 secure, cgiargs)
        elif not args['new_style']:
            prog = sroot + "/bin/slapd/admin/bin/ds_create"
            if not os.access(prog, os.X_OK):
                prog = sroot + "/bin/slapd/admin/bin/ds_newinstance"
            DSAdminTools.cgiFake(sroot, verbose, prog, cgiargs)
        else:
            prog = ''
            if args['have_admin']:
                prog = get_sbin_dir(sroot, prefix) + PATH_SETUP_DS_ADMIN
            else:
                prog = get_sbin_dir(sroot, prefix) + PATH_SETUP_DS

            if not os.path.isfile(prog):
                log.error("Can't find file: %r, removing extension" % prog)
                prog = prog[:-3]

            content = formatInfData(args)
            DSAdminTools.runInfProg(prog, content, verbose)

        newconn = lib389.DSAdmin(args['newhost'], args['newport'],
                          args['newrootdn'], args['newrootpw'], args['newinstance'])
        newconn.isLocal = isLocal
        # Now the admin should have been created
        # but still I should have taken all the required infos
        # before.
        if args['have_admin'] and not args['setup_admin']:
            newconn.asport = asport
            newconn.cfgdsuser = args['cfgdsuser']
            newconn.cfgdspwd = args['cfgdspwd']
        return newconn

    @staticmethod
    def createAndSetupReplica(createArgs, repArgs):
        # pass this sub two dicts - the first one is a dict suitable to create
        # a new instance - see createInstance for more details
        # the second is a dict suitable for replicaSetupAll - see replicaSetupAll
        conn = DSAdminTools.createInstance(createArgs)
        if not conn:
            print "Error: could not create server", createArgs
            return 0

        conn.replicaSetupAll(repArgs)
        return conn


class MockDSAdmin(object):
    host = 'localhost'
    port = 22389
    sslport = 0

    def __init__(self, dict_=None):
        if dict_:
            self.host = dict_['host']
            self.port = dict_['port']
            if 'sslport' in dict_:
                self.sslport = dict_['sslport']
        
    def __str__(self):
        if self.sslport:
            return 'ldaps://%s:%s' % (self.host, self.sslport)
        else:
            return 'ldap://%s:%s' % (self.host, self.port)
