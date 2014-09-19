##########################################
# This is a modifed version of the panChange.py script from the Palo Alto App 
# This script is meant to be use with Splunk Enterprise Security.
# Author of the Update: Jose E Hernandez
# Description: This is a modifed version of the panChange.py script from the Palo Alto App 
#              This script is meant to be use with Splunk Enterprise Security.
# Udpates:
#       * crendetials now stored encrypted using credential manager with ES
#       * multiple firewalls supported
#       * configuration file moved to default/pa.conf
##########################################
# Original Documentation Below
###########################################
# Version 0.1
# Extremely Experimental
# author: monzy@splunk.com
# About this script:
# Given an IP address, adds or removes the IP from an address group
# The script assumes that you have firewall policy setup that blocks
# traffic for a given group, e.g. a badActors group.
# It is important to recognize that this script does NOT modify a firewall rule.
# It only adds/removes address objects.
# So if a rule operates on an Address Group, this scripts add/remove will impact
# that rule/policy.
############################################
# How to Use this script
# in the example below, we are blocking all ip's returned by the search
# example1: index=pan_logs 1.1.1.1 | stats dc(dst_ip) by dst_ip | panblock action="add" group="badboys"
# Adds the IP 1.1.1.1
# example2: index=pan_logs wine | stats dc(dst_hostname) by dst_hostname | panblock action="rem" group="badboys" device="sales-fw"
# Removes all dst_hostnames returned by the search from the sales firewall from the badboys group
###########################################
# Known issues:
# Very limited error checking
# Errors may not reported in the Splunk UI
# Changes do not get implemented on Panorama (i am happy to work with someone to add this feature)
###########################################
# DEFAULTS
ACTION = 'add'
# This is a default actor.
ACTOR = '1.1.1.1'
# if you DO want to go through a proxy, e.g., HTTP_PROXY={squid:'2.2.2.2'}
HTTP_PROXY = {}

#########################################################
# Do NOT modify anything below this line unless you are
# certain of the ramifications of the changes
#########################################################

import splunk.Intersplunk # so you can interact with Splunk
import splunk.entity as entity # for splunk config info
import urllib2 # make http requests to PAN firewall
import sys # for system params and sys.exit()
import re # regular expressions checks in PAN messages
import splunk.mining.dcutils as dcu
import ConfigParser # to parse out the pa.conf file
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path # to grab the default splunk path
import splunk.rest
import json

logger = dcu.getLogger()
# set path of config
panconf = make_splunkhome_path(["etc","apps","SA-Mitigation","default","pan.conf"])
# read config file
config = ConfigParser.RawConfigParser()
config.read(panconf)

#Assign PA IP
PAN = config.get('PAN','IP')

#Assign BADACTORS group name
BADACTORS = config.get('PAN','GROUP')

## Major props to Ledion. copying his function, verbatim and then adding comments and traceback and logging
## http://blogs.splunk.com/2011/03/15/storing-encrypted-credentials/
## access the credentials in /servicesNS/nobody/<YourApp>/admin/passwords

def getCredentials(sessionKey):
  '''Given a splunk sesionKey returns a clear text user name and password from a splunk password container'''
    USERNAME =''
    PASSWORD =''
    #make a rest call to get passwords from credential manager
    response,content = splunk.rest.simpleRequest('storage/passwords', sessionKey=sessionKey, getargs={'output_mode':'json'}, postargs=None, method='GET', raiseAllErrors=False, proxyMode=False, rawResult=False, timeout=None, jsonargs=None)
    #format output as json
    content = json.loads(content)

    #look for the realm of PAN and resturn the credentials
    for items in content['entry']:
        if items['content']['realm'] == 'PAN':
                USERNAME = (item['content']['username']
                PASSWORD = item['content']['clear_password']
    return USERNAME,PASSWORD    
## Major props to Ledion. copying his function, verbatim and then adding comments and traceback and logging

def createOpener():
  '''Create a generic opener for http. This is particularly helpful when there is a proxy server in line'''
  # Thanks to: http://www.decalage.info/en/python/urllib2noproxy
  proxy_handler = urllib2.ProxyHandler(HTTP_PROXY)
  opener = urllib2.build_opener(proxy_handler)
  urllib2.install_opener(opener)
  return opener

def getKey(PAN, PANUSER, PANPASS):
  ''' Logs into the PAN firewall and obtains a PAN session key'''
  # create an opener object
  opener = createOpener()
  try:
    # the url for the PAN
    panReq =  urllib2.Request('https://'+PAN+'/api/?type=keygen&user='+PANUSER+'&password='+PANPASS)
    # make the request
    req = opener.open(panReq)
  except:
    sys.exit(-1)
  # the result of the URL request
  result = req.read()
  # get the status of the result
  try:
    sm = re.search(r"success",result).group(0)
    if sm == 'success' :
      status = 'success'
  except:
    sys.exit(-1)
  # parse the key from the result
  key = result.split("</key>")[0].split("<key>")[1]
  return key

def checkAddr(address):
  '''Check if an address is a FQDN or IP with some netmask. Return the appropriate uri for PAN api'''
  # element is everything after the element= field in the PAN api
  # re pattern for IP address
  ippat = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
  # re pattern for fully qualified domain name (could be stricter)
  fqdnpat = '\w+[.-]'
  # is element an IP address
  if re.match(ippat, address) != None :
    ipuri = '<ip-netmask>'+address+'/32</ip-netmask>'
    return ipuri
  if re.match(fqdnpat, address) != None :
    fqdnuri = '<fqdn>'+address+'</fqdn>'
    return fqdnuri

def panorama():
  ''' Interact with PANorama'''
  #Set dynamic address object (with LinkID) at Panorama level, commit
  #https://pm-panorama/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='splunktastic']/address/entry[@name='test-add']&element=<dynamic>test1</dynamic>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09
  #https://pm-panorama/api/?type=commit&action=all&cmd=<commit-all><shared-policy><device-group>splunktastic</device-group></shared-policy></commit-all>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09
  #Map IPs to correct UserID
  #https://pm-panorama/api/?type=user-id&action=set&cmd=<uid-message><version>1.0</version><type>update</type><payload><login><entry name="domain\uid1" ip="10.1.1.1" timeout="20"></entry></login></payload></uid-message>&key=LUFRPT14MW5xOEo1R09KVlBZNnpnemh0VHRBOWl6TGM9bXcwM3JHUGVhRlNiY0dCR0srNERUQT09&target=0006C107916
  return 0

def addActor(PAN, key, VSYS, ACTOR, BADACTORS):
  '''Creates an address object then add the object to an Address group'''
  # create an opener object
  opener = createOpener()
  # create the address object
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=config&action=set&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address/entry[@name='+"'"+ACTOR+"'"+']&element='+checkAddr(ACTOR))
  req = opener.open(panReq)
  # add the address object to the BADACTORS group
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=config&action=set&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address-group/entry[@name='+"'"+BADACTORS+"'"+']&element=<member>'+ACTOR+'</member>')
  req = opener.open(panReq)
  return 0

def remActor(PAN, key, VSYS, ACTOR, BADACTORS):
  '''Remove an address object from the address-group then remove the addres object '''
  # create an opener object
  opener = createOpener()
  # first we remove him from the badactors group
  #panReq = urllib2.Request('https://'+PAN+'/api/?type=config&action=delete&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address-group/entry[@name='+"'"+BADACTORS+"'"+']&element=<member>'+ACTOR+'</member>')
  #req = opener.open(panReq)
  # then we remove him all together
  #panReq = urllib2.Request('https://'+PAN+'/api/?type=config&action=delete&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address/entry[@name='+"'"+ACTOR+"'"+']')
  #req = opener.open(panReq)
  panReq = urllib2.Request('https://'+PAN+'/api/?type=config&action=delete&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address-group/entry[@name='+"'"+BADACTORS+"'"+']/member[text()='+"'"+ACTOR+"'"+']')
  req = opener.open(panReq)
  panReq = urllib2.Request('https://'+PAN+'/api/?type=config&action=delete&key='+key+'&xpath=/config/devices/entry/vsys/entry[@name='+"'"+VSYS+"'"+']/address/entry[@name='+"'"+ACTOR+"'"+']')
  req = opener.open(panReq)
  return 0

def commitConfig(PAN, key):
  '''Save the changes made to the address objects'''
  # create an opener object
  opener = createOpener()
  panReq =  urllib2.Request('https://'+PAN+'//api/?type=commit&cmd=<commit></commit>&key='+key)
  req = opener.open(panReq)
  return 0

def block(result):
  key = getKey(PAN, PANUSER, PANPASS)
  if ACTION == 'add':
    addActor(PAN, key, VSYS, str(result[result.keys()[0]]), BADACTORS)
  elif ACTION == 'rem':
    remActor(PAN, key, VSYS, str(result[result.keys()[0]]), BADACTORS)
  else:
    return ['bad action', key]
  return ["action submitted", key]

args, kwargs = splunk.Intersplunk.getKeywordsAndOptions()
#parse the kwargs for ACTION, VSYS, PAN
if kwargs.has_key('action'):
  ACTION = kwargs['action']
if kwargs.has_key('device'):
  PAN = kwargs['device']
if kwargs.has_key('vsys'):
  VSYS = kwargs['vsys']
if kwargs.has_key('group'):
  BADACTORS = kwargs['group']

# an empty dictionary. it will be used to hold system values
settings = dict()
# results contains the data from the search results and settings contains the sessionKey that we can use to talk to splunk
results,unused,settings = splunk.Intersplunk.getOrganizedResults()
# get the sessionKey
sessionKey = settings['sessionKey']
# get the user and password using the sessionKey
PANUSER, PANPASS = getCredentials(sessionKey)

try:
  for result in results:
    if (result.has_key('src_ip')\
    or result.has_key('dst_ip') \
    or result.has_key('ip') \
    or result.has_key('hostname') \
    or result.has_key('dst_hostname') \
    or result.has_key('dest_host') \
    or result.has_key('domain') \
    or result.has_key('clientip') ):
      blockresult = block(result)
      result["status"] = blockresult[0]
      key = blockresult[1]
    # for test purposes
    elif (len(result) == 2) and result.has_key('test'):
      result["status"] = ["this is the sessionKey. not printing the password :p " + sessionKey]
    else:
      result["status"] = 'empty or invalid field vlue'

  #after all the addresses have been processed, commit the config
  commitConfig(PAN, key)
except Exception, e:
  import traceback
  stack =  traceback.format_exc()
  if isgetinfo:
    splunk.Intersplunk.parseError(str(e))

  results = splunk.Intersplunk.generateErrorResults(str(e))
  logger.warn(stack)

# output results
splunk.Intersplunk.outputResults(results)
