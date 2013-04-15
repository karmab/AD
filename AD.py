#!/usr/bin/python
"""
changes given ldap user attributes
"""

#based on http://www.packtpub.com/article/python-ldap-applications-ldap-opearations
import ldap,sys,os,getpass,optparse,datetime,ldap.modlist as modlist,socket
import ConfigParser


__author__ = "Karim Boumedhel"
__credits__ = ["Karim Boumedhel"]
__license__ = "GPL"
__version__ = "0.1"
__maintainer__ = "Karim Boumedhel"
__email__ = "karimboumedhel@gmail.com"
__status__ = "Production"

ERR_NOADFILE="You need to create a correct AD.ini file in your home directory.Check documentation"

parser = optparse.OptionParser("Usage: %prog [options] user")
parser.add_option("-u", "--unlock", dest="lockoutTime", action="store_true", help="Unlock user")
parser.add_option("-n", "--uidnumber", dest="uidNumber", type="string", help="Change uidnumber")
parser.add_option("-i", "--info", dest="info", action="store_true", help="Grab user info")
parser.add_option("-a", "--add", dest="add", action="store_true", help="Add new user")
parser.add_option("-c", "--client", dest="client", type="string",help="Specify Client")
parser.add_option("-d", "--delete", dest="delete", action="store_true", help="Delete user")
parser.add_option("-l", "--listclients", dest="listclients", action="store_true", help="List clients")
parser.add_option("-m", "--mail", dest="mail", type="string",help="User mail")
parser.add_option("-g", "--groups", dest="groups", type="string",help="Group.Can be a list separate by ;")
parser.add_option("-p", "--password", dest="unicodePwd", action="store_true", help="Password")
parser.add_option("-P", "--phone", dest="homePhone", type="string",help="Phone")
parser.add_option("-b", "--boy", dest="boy", type="string", help="User to add(Name Surname 2ndName)")
parser.add_option("-s", "--shell", dest="loginShell", type="string", help="Shell")
parser.add_option("-S", "--search", dest="search", type="string", help="Search users using the provided string")
parser.add_option("-t", "--type", dest="usertype", type="string", help="Type(internal o external)")
parser.add_option("-H", "--homedirectory", dest="unixHomeDirectory", type="string", help="Homedirectory")
parser.add_option("-U", "--uid", dest="uid", type="string", help="Change uid(username)")
parser.add_option("-X", "--pager", dest="pager", type="string", help="Change pager")
parser.add_option("-9", "--switchclient", dest="switchclient", type="string", help="Switch default client")


(options, args) = parser.parse_args()
lockoutTime=options.lockoutTime
unixHomeDirectory=options.unixHomeDirectory
lockoutTime=options.lockoutTime
unicodePwd=options.unicodePwd
uid=options.uid
groups=options.groups
uidNumber=options.uidNumber
info=options.info
pager=options.pager
add=options.add 
boy=options.boy
client=options.client
listclients=options.listclients
switchclient = options.switchclient
homePhone=options.homePhone
delete=options.delete
usertype=options.usertype
mail=options.mail
loginShell=options.loginShell
search=options.search
extragroups=None
secure=False

if not lockoutTime and not unixHomeDirectory and not unicodePwd and not info and not uid and not pager and not add and not delete and not mail and not uidNumber and not homePhone and not loginShell and not search and not listclients and not groups and not switchclient:
 print "No actions specified,leaving..."
 sys.exit(1)

#parse ADS for specific client
ADconffile=os.environ['HOME']+"/AD.ini"
if not os.path.exists(ADconffile):
 print "Missing %s in your  home directory.Check documentation" % ADconffile
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
 if default.has_key("client"):print "Current default client is: %s" % (default["client"])
 sys.exit(0)

if switchclient:
 if switchclient not in ads.keys():
  print "Client not defined...Leaving"
 else:
  mod = open(ADconffile).readlines()
  f=open(ADconffile,"w")
  for line in mod:
   if line.startswith("client"):
    f.write("client=%s\n" % switchclient)
   else:
    f.write(line)
  f.close()
  print "Default Client set to %s" % (switchclient)
 sys.exit(0)

try:
 basedn=ads[client]['basedn']
 authdn=ads[client]['authdn']
 authpw=ads[client]['authpw']
 domain=ads[client]['domain']
 timetoexpire=int(ads[client]['timetoexpire'])*86400
 ldapserver=ads[client]['server']
 if ads[client].has_key("secure") and "rue" in ads[client]['secure']:secure=True
 if secure:
  ldapuri="ldaps://%s" % (ldapserver)
  certpath=ads[client]['certpath']
 else: 
  ldapuri='ldap://%s'% (ldapserver)
 if ads[client].has_key("internaldn"):internaldn=ads[client]['internaldn']
 if ads[client].has_key("externaldn"):externaldn=ads[client]['externaldn']
 if ads[client].has_key("homerootdir"):homerootdir=ads[client]['homerootdir']
 if ads[client].has_key("extragroups"):extragroups=ads[client]['extragroups'].split(";")
except KeyError,e:
 print "Problem parsing your ini file:Missing parameter %s" % e
 os._exit(1)

if secure:
 ldap.set_option( ldap.OPT_X_TLS_CACERTFILE , certpath )
 #ldap.set_option( ldap.OPT_X_TLS_REQUIRE_CERT , 1 )
 ldap.set_option( ldap.OPT_X_TLS_REQUIRE_CERT , ldap.OPT_X_TLS_ALLOW)
ldap.set_option(ldap.OPT_NETWORK_TIMEOUT , 10 )
ldap.set_option ( ldap.OPT_REFERRALS , 0 )

try:
 f=socket.gethostbyname(ldapserver)
except socket.gaierror:
 print "ip associated to %s not found" % (ldapserver)
 print "update your /etc/hosts or dns config"
 os._exit(1)

#search users
if search:
 try:
  userfilter = "cn=*%s*" % search
  attrs = ['mail','homePhone','sAMAccountName']
  c = ldap.initialize(ldapuri)
  c.simple_bind_s(authdn,authpw)
  #we only grab first entry, as other corresponds to LDAP internal answers, hence useless for us
  res=c.search_s( basedn, ldap.SCOPE_SUBTREE, userfilter, attrs)
  c.unbind()
  for r in res:
   i=1
   if r[0]:
    print r[0]
    if len(r[1].keys())==0:
     print "\n"
     pass
    for k in sorted(r[1].keys()):
     print "%s:%s" % (k,r[1][k][0])
     if i==len(r[1].keys()):print "\n"
     i=i+1
  os._exit(0)
 except:
  print "There was some kind of Problem"
  os._exit(5)

#handle new user
if add:
 msSFU30NisDomain=domain
 if not loginShell:loginShell="/bin/bash"
 objectClass=["top","person","organizationalPerson","user"]
 objectCategory="CN=Person,CN=Schema,CN=Configuration,%s " % basedn
 countryCode="0"
 userAccountControl="512"
 lockoutTime="0"
 if not boy:boy=raw_input("Enter username(Name Surname 2eSurname):\n")
 if len(boy.split(" "))!=3:
  print "Usage: Name Surname 2eSurname,Leaving..."
  sys.exit(0)
 boy=boy.split(" ")
 boy=[boy[0].capitalize(),boy[1].capitalize(),boy[2].capitalize()]
 cn,givenName,sn,uid="%s %s %s" %(boy[0],boy[1],boy[2]),boy[0],"%s %s" %(boy[1],boy[2]),"%s.%s" %(boy[0].lower(),boy[1].lower())
 displayName,name=cn,cn
 sAMAccountName,sAMAccountType,msSFU30Name,msSFU30NisDomain,userPrincipalName=uid,"805306368",uid,domain,"%s@%s.local" % (uid,domain)
 createattrs={"objectClass":objectClass,"objectCategory":objectCategory,"cn":cn,"givenName":givenName,"sn":sn,"uid":uid,"displayName":displayName,"name":name,"sAMAccountName":sAMAccountName,"msSFU30Name":msSFU30Name,"userPrincipalName":userPrincipalName,"msSFU30NisDomain":msSFU30NisDomain,"loginShell":loginShell,"userAccountControl":userAccountControl}
 groupfilter="(&(objectClass=organizationalUnit)(ou=Groups))"
 groups=[]
 c = ldap.initialize(ldapuri)
 c.simple_bind_s(authdn,authpw)
 groupres=c.search_s( basedn, ldap.SCOPE_SUBTREE, groupfilter, ['cn'])
 c.unbind()

 #get primary group 
 print "Available Groups:"
 for ent in groupres:
  if ent[0] !=None:groups.append(ent[0]) 
 for g in groups:print g
 group=raw_input("Select Group for this user:\n")
 if group not in groups:
  print "Invalid Group.Failing..."
  sys.exit(1)
 if not unixHomeDirectory and homerootdir:createattrs["unixHomeDirectory"]="%s/%s" % (homerootdir,uid)
 #get gid filter
 gids=[]
 gidfilter="(&(objectClass=group)(gidnumber=*))"
 c = ldap.initialize(ldapuri)
 c.simple_bind_s(authdn,authpw)
 gidres=c.search_s( basedn, ldap.SCOPE_SUBTREE, gidfilter, ['gidNumber','cn'])
 c.unbind()
 for g in gidres:
  if g[0] and group in g[0]:gids.append([g[1]['cn'][0],g[1]['gidNumber'][0]])
 if len(gids) >1:
  print "Several matching groups found.Leaving"
  sys.exit(1)
 groupname,gidnumber=gids[0][0],gids[0][1]
 createattrs["gidNumber"]=gidnumber

 #get highest uid within this group
 uidmax=0
 c = ldap.initialize(ldapuri)
 c.simple_bind_s(authdn,authpw)
 uidfilter="(&(objectClass=person)(gidnumber=%s))" % (gidnumber)
 uidres=c.search_s(basedn, ldap.SCOPE_SUBTREE, uidfilter, ['uidNumber','cn'])
 #get basedn to create new user making assumption that it should be similar to allready existing users
 #also grab CN of the member with highest uid, as it will be the one used to grab which groups should our new user belongs to
 userbasedn=uidres[0][0].replace("CN=%s," % uidres[0][1]["cn"][0],"")
 c.unbind()
 for el in uidres:
  if type(el[1]) is dict and int(el[1]["uidNumber"][0])>uidmax:
   uidmax=int(el[1]["uidNumber"][0])
   winner=el[0]
 uidmax=int(uidmax)+1
 createattrs["uidNumber"]=str(uidmax)
 if not mail:mail=raw_input("Enter mail address:\n")
 if homePhone:createattrs["homePhone"]=homePhone

 dn="CN=%s,%s" % (cn,userbasedn)
 distinguishedName=dn
 createattrs["distinguishedName"]=distinguishedName

 #grab additional groups based on the assumption that user should be added to all groups containing its group name...
 #a switch should be put to activate this feature maybe
 winnerfilter="uidNumber=%d" % (uidmax-1)
 c = ldap.initialize(ldapuri)
 c.simple_bind_s(authdn,authpw)
 winnerres=c.search_s( basedn, ldap.SCOPE_SUBTREE, winnerfilter, ['memberOf'])
 c.unbind()
 for g in winnerres:
  if g[0] !=None:allgroups=(g[1]['memberOf'])

if unicodePwd or add:
 newpass=getpass.getpass("Enter Password:")
 newpass2=getpass.getpass("Verify:")
 if newpass != newpass2:
  print "Passwords dont match"
  sys.exit(1)

if add:
 newpass='"'+newpass+'"'
 createattrs["unicodePwd"]=newpass.encode("utf-16-le")
 createldif=modlist.addModlist(createattrs)
 c = ldap.initialize(ldapuri)
 c.simple_bind_s(authdn,authpw)
 c.add_s(dn,createldif)
 print "User created"
 #add user to a list of groups
 mod=( ldap.MOD_ADD, 'member', dn  )
 mod=[mod]
 if extragroups:
  for g in extragroups:c.modify_s(g,mod)
 if len(allgroups)>0:
  for g in allgroups:c.modify_s(g,mod)
 c.modify_s(dn,[( ldap.MOD_REPLACE, 'mail', mail )])
 c.unbind()
 sys.exit(0)

if len(args) != 1:
 print "Usage: %s [options] usuario" %  sys.argv[0]
 sys.exit(1)
username=args[0]

#2-check there s an LDAP user with this login 
try:
 userfilter = "sAMAccountName="+username	
 if info or delete:attrs = ['cn','uid','uidNumber','unixHomeDirectory','lockoutTime','loginShell','pwdLastSet','mail','homePhone','pager','memberOf']
 else:
  attrs = ['cn']
 c = ldap.initialize(ldapuri)
 c.simple_bind_s(authdn,authpw)
 #we only grab first entry, as other corresponds to LDAP internal answers, hence useless for us
 res=c.search_s( basedn, ldap.SCOPE_SUBTREE, userfilter, attrs)[0]
 c.unbind()
 if not res[0]:
  print "Wrong username!"
  os._exit(4)
 usercn=res[0]
except:
 print "Problem searching your user!" 
 os._exit(5) 
if delete:
 confirm=raw_input("tape Y if you re sure you want to delete the user %s\n" % (usercn) )
 if confirm !="Y":
  print "action not confirmed.Not doing anything"
  sys.exit(1)
 c = ldap.initialize(ldapuri)
 c.simple_bind_s(authdn,authpw)
 c.delete_s(usercn)
 print "User sucessfully deleted"
 sys.exit(0)

if info:
 print "dn:%s" % (usercn)
 for data in sorted(res[1].keys()):
  if data=='pwdLastSet':
   expires=int(res[1][data][0])/10000000 -11644473600
   exp=datetime.datetime.fromtimestamp(expires+timetoexpire).strftime('%Y-%m-%d')
   print "%s:%s" % ('fecha de expiracion',exp)
  elif data=='lockoutTime':
   if res[1][data][0]=="0":
    print "User locked:No"
   else:  
    print "User locked:Yes"
  elif data=='memberOf':
    for g in res[1][data]:print "MemberOf:%s" % g
  else:  
   print "%s:%s" % (data,res[1][data][0])
 
 sys.exit(0)


changelist=[]
if unixHomeDirectory:changelist.append(( ldap.MOD_REPLACE, 'unixHomeDirectory', unixHomeDirectory ))
if lockoutTime:changelist.append(( ldap.MOD_REPLACE, 'lockoutTime', "0" ))
if mail:changelist.append(( ldap.MOD_REPLACE, 'mail', mail ))
if homePhone:changelist.append(( ldap.MOD_REPLACE, 'homePhone', homePhone ))
if uidNumber:changelist.append(( ldap.MOD_REPLACE, 'uidNumber', uidNumber ))
if loginShell:changelist.append(( ldap.MOD_REPLACE, 'loginShell', loginShell ))
if uid:
 changelist.append(( ldap.MOD_REPLACE, 'uid', uid ))
 changelist.append(( ldap.MOD_REPLACE, 'msSFU30Name', uid ))
if unicodePwd:
 newpass='"'+newpass+'"'
 passlist=[( ldap.MOD_REPLACE, 'unicodePwd', newpass.encode("utf-16-le") ) , ( ldap.MOD_REPLACE, 'unicodePwd', newpass.encode("utf-16-le") ) ] 
if pager:changelist.append(( ldap.MOD_REPLACE, 'pager', pager ))


con = ldap.initialize(ldapuri)
try:
 con.simple_bind_s(authdn,authpw)
 for mod in changelist:
  change=mod[1]
  mod=[mod]
  con.modify_s(usercn,mod)
  print "Change applied for %s" % (change)
 if groups:
  modg=( ldap.MOD_ADD, 'member', usercn )
  modg=[modg]
  groups=groups.split(";")
  for g in groups:
   con.modify_s(g,modg)
  print "Groups changed"
 if unicodePwd:
  con.modify_s(usercn,passlist)
  print "Password changed"
 con.unbind()
except :
 print "There was some kind of problem,try again..."
 con.unbind()
 os._exit(7)
