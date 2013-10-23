#!/usr/bin/python
"""
changes/create/delete ldap sudo roles
"""

#based on http://www.packtpub.com/article/python-ldap-applications-ldap-opearations
import ldap,sys,string,getpass,optparse,time,datetime
import os
import ConfigParser


__author__ = "Karim Boumedhel"
__credits__ = ["Karim Boumedhel"]
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "Karim Boumedhel"
__email__ = "karimboumedhel@gmail.com"
__status__ = "Production"

ERR_NOADFILE="You need to create a correct AD.ini file in your home directory.Check documentation"


parser = optparse.OptionParser("Usage: %prog [options] sudorole")
parser.add_option("-a", "--add", dest="add", action="store_true", help="Create new sudorole")
parser.add_option("-c", "--command", dest="command", type="string" , help="Add command to given sudorole.Can be a list separated by commas")
parser.add_option("-d", "--delete", dest="delete", action="store_true", help="Delete given sudorole")
parser.add_option("-l", "--short", dest="shortlistsudos", action="store_true", help="List all sudoroles in a short way")
parser.add_option("-q", "--quit", dest="quitcommand", type="string" , help="Quit command to given sudorole")
parser.add_option("-r", "--removeuser", dest="removeuser", type="string" , help="Remove user from given sudorole")
parser.add_option("-u", "--user", dest="user", type="string" , help="Add user to given sudorole.Can be a list separated by commas")
parser.add_option("-C", "--client", dest="client", type="string" , help="Client")
parser.add_option("-D", "--removehost", dest="removehost", type="string" , help="Remove host from given sudorole")
parser.add_option("-H", "--host", dest="host", type="string" , help="Add host to given sudorole.Can be a list separated by commas")
parser.add_option("-L", "--list", dest="listsudos", action="store_true", help="List all sudoroles")
parser.add_option("-B", "--listclients", dest="listclients", action="store_true", help="List clients")

(options, args) = parser.parse_args()
listsudos=options.listsudos
shortlistsudos=options.shortlistsudos
command=options.command
quitcommand=options.quitcommand
user=options.user
host=options.host
client=options.client
listclients=options.listclients
removeuser=options.removeuser
removehost=options.removehost
add=options.add
delete=options.delete

if not shortlistsudos and not listsudos and not user and not host and not command and not removeuser and not removehost and not add and not delete and not quitcommand:
    print "No actions specified,leaving..."
    sys.exit(1)

if user and len(args) != 1:
    print "Usage: %s [options] sudorole" %  sys.argv[0]
    sys.exit(1)
if host and len(args) != 1:
    print "Usage: %s [options] sudorole" %  sys.argv[0]
    sys.exit(1)
if command and len(args) != 1:
    print "Usage: %s [options] sudorole" %  sys.argv[0]
    sys.exit(1)
if quitcommand and len(args) != 1:
    print "Usage: %s [options] sudorole" %  sys.argv[0]
    sys.exit(1)
if removeuser and len(args) != 1:
    print "Usage: %s [options] sudorole" %  sys.argv[0]
    sys.exit(1)
if removehost and len(args) != 1:
    print "Usage: %s [options] sudorole" %  sys.argv[0]
    sys.exit(1)
if delete and len(args) != 1:
    print "Usage: %s [options] sudorole" %  sys.argv[0]
    sys.exit(1)


#parse ADS for specific client
if os.path.exists("AD.ini"):
    ADconffile="AD.ini"
else:
    ADconffile=os.environ['HOME']+"/AD.ini"
if not os.path.exists(ADconffile):
    print "Missing %s in your  home directory.Check documentation" % cobblerconffile
    sys.exit(1)
try:
    c = ConfigParser.ConfigParser()
    c.read(ADconffile)
    ads={}
    default={}
    for ad in c.sections():
        for option in  c.options(ad):
            if ad=="default":
                default[option]=c.get(ad,option)
                continue
            if not ads.has_key(ad):
                ads[ad]={option : c.get(ad,option)}
            else:
                ads[ad][option]=c.get(ad,option)
except:
    print ERR_NOADFILE
    os._exit(1)

if not client:
    try:
        client=default['client']
    except:
        print "No client defined as default in your ini file or specified in command line"
        os._exit(1)

if not ads.has_key(client):
    print "Missing Client in your ini file"
    sys.exit(1)

if listclients:
    print "Available Clients:"
    for cli in  sorted(ads):
        if cli=="default":continue
        print cli
    sys.exit(0)

try:
    basedn=ads[client]['basedn']
    authdn=ads[client]['authdn']
    authpw=ads[client]['authpw']
    ldapserver=ads[client]['ldapserver']
    ldapuri='ldaps://'+ldapserver
    certpath=ads[client]['certpath']
    sudodn=ads[client]['sudodn']
except KeyError,e:
    print "Problem parsing your ini file:Missing parameter %s" % e
    os._exit(1)

ldap.set_option( ldap.OPT_X_TLS_CACERTFILE , certpath )
ldap.set_option ( ldap.OPT_REFERRALS , 0 )
ldap.set_option( ldap.OPT_X_TLS_REQUIRE_CERT , 1 )
ldap.set_option(ldap.OPT_NETWORK_TIMEOUT , 10 )

if listsudos or shortlistsudos:
    shortlistresults=[]
    listresults={}
    if len(args) !=1:
        namefilter="objectClass=sudoRole"
    else:
        namefilter = "(&(objectClass=sudoRole)(name=%s))" % args[0]
    attrs=['name','sudoUser','sudoHost','sudoCommand','sudoOption']
    c = ldap.initialize(ldapuri)
    c.simple_bind_s(authdn,authpw)
    res=c.search_s( basedn, ldap.SCOPE_SUBTREE, namefilter, attrs)
    c.unbind()
    for r in res:
        if r[0]:
            if shortlistsudos:
                shortlistresults.append(r[0])
                continue
            else:
                listresults[r[0]]=[]
            for k in sorted(r[1].keys()):
                if len(r[1][k])==1:
                    listresults[r[0]].append("%s:%s" % (k,r[1][k][0]))
                else:
                    listresults[r[0]].append("%s:%s" % (k," ".join(r[1][k])))
    if shortlistsudos:
        for r in sorted(shortlistresults):print r
    else:
        for k in sorted(listresults.keys()):
            print k
            for el in listresults[k]:print el
            print "\n"
    sys.exit(0)

#handle add here
if add:
    sudoOption="!authenticate"
    name=raw_input("Enter name for your new sudorole:\n")
    sudocn="CN=%s,%s" % (name,sudodn)
    attrs=[("objectClass",["top","sudoRole"]),("objectCategory","CN=sudoRole,CN=Schema,CN=Configuration,%s" % basedn),("sudoOption",sudoOption)]
    if name=="":
        print "name cant be blank.leaving..."
        sys.exit(1)
    attrs.append(("name",name))
    attrs.append(("cn",name))
    attrs.append(("distinguishedName",sudocn))
    for element in ["sudoCommand","sudoHost","sudoUser"]:
        data=raw_input("enter %s.If you need several elements,separate them with a comma\n" % element)
        if data=="":
            print "%s cant be blank.leaving..." % element
            sys.exit(1)
        attrs.append((element,data.split(",")))
    c = ldap.initialize(ldapuri)
    c.simple_bind_s(authdn,authpw)
    c.add_s(sudocn,attrs)
    print "Sudorole created"
    sys.exit(0)

#first verify if there is a sudorole asociated to this name
if user or host or command or removeuser or removehost or delete or quitcommand:
    sudo=args[0]
    namefilter = "(&(objectClass=sudoRole)(name=%s))" % sudo
    c = ldap.initialize(ldapuri)
    c.simple_bind_s(authdn,authpw)
    #we only grab first entry, as other corresponds to LDAP internal answers, hence useless for us
    res=c.search_s( basedn, ldap.SCOPE_SUBTREE, namefilter)[0]
    c.unbind()
    if not res[0]:
        print "Wrong sudo name"
        sys.exit(4)
    sudocn=res[0]

#handle delete here
if delete:
    c = ldap.initialize(ldapuri)
    c.simple_bind_s(authdn,authpw)
    c.delete_s(sudocn)
    print "Sudorole deleted"
    sys.exit(0)

changelist=[]
if user:changelist.append(( ldap.MOD_ADD, 'sudoUser', user.split(",") ))
if host:changelist.append(( ldap.MOD_ADD, 'sudoHost', host.split(",") ))
if command:changelist.append(( ldap.MOD_ADD, 'sudoCommand', command.split(",") ))
if quitcommand:changelist.append(( ldap.MOD_DELETE, 'sudoCommand', quitcommand.split(",") ))
if removeuser:changelist.append(( ldap.MOD_DELETE, 'sudoUser', removeuser.split(",") ))
if removehost:changelist.append(( ldap.MOD_DELETE, 'sudoHost', removehost.split(",") ))
con = ldap.initialize(ldapuri)
try:
    con.simple_bind_s(authdn,authpw)
    for mod in changelist:
        change=mod[1]
        mod=[mod]
        con.modify_s(sudocn,mod)
        print "Change applied for %s" % (change)
    con.unbind()
except :
    print "There was some kind of problem,try again..."
    sys.exit(7)
