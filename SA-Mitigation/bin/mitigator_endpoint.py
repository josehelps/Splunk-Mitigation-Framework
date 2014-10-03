import urllib
import urllib2
import json
import time
import logging
import logging.handlers

import splunk.Intersplunk as si
import splunk.rest
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

def setup_logger():
    """
    Sets up a logger for the Mitigator search command to track issued 
    mitigation tasks.
    """
    logger = logging.getLogger('mitigator')
    # Prevent the log messgaes from being duplicated in the python.log
    #    AuthorizationFailed
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    
    file_handler = logging.handlers.RotatingFileHandler(
                    make_splunkhome_path(['etc', 'apps', 'SA-Mitigation', 'logs',
                                          'mitigator.log']),
                                        maxBytes=25000000, backupCount=5)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logger()

class Mitigator(object):
    """
    Mitigator Class
        This class is used for issuing mitigation tasks to remote forwarders
        containing the SA-LWF_Mitigater Splunk App.
    """
    
    ## Forwarder Management Port 
    _MGMT_PORT = ':8089'
    
    ## REST Endpoint for issuing Splunk Searches
    _SEARCH_ENDPOINT = '/servicesNS/nobody/search/search/jobs/export'
    
    ## REST Endpoint for authentication. Used to obtain a session key
    _AUTH_ENDPOINT = '/servicesNS/nobody/search/auth/login'
    
    def __init__(self, system, localSessionKey):
        """
        Mitigator Constructor
            The constructor will attempt to obtain a session key for the remote
            instance. If this fails the Mitigator will be unable to issue a 
            mitigation task to the remote forwarder.
        @param system: The system (hostname or ip) in which the mitigation task
        is being issued to.
        @param uname: Username for the remote Splunk instance
        @param passwd: Password for the remote Splunk instance
        """
        self.queueSearch = ("| inputlookup proc_queue_template " + 
                            "| eval pid={0} | eval time={1} | fields time, " + 
                            "pid | outputlookup append=T max=1 process_queue")
        self._setHost(system)
        self._time = str(int(time.time()))
        self._setLocalSessionKey(localSessionKey)
        self.sessionKey = self._requestSessionKey()
        
        logger.info("Mitigator Established for System: " + self._host)


    def _setLocalSessionKey(self, local_session_key):
        """
        Private Method: _setLocalSessionKey
            Used to set the local session key for the Splunk instance where 
            SA-Mitigation resides.
        """
        self._localSessionKey = str(local_session_key)

    def _setHost(self, the_system):
        """
        Private Method: _setHost
            Method used to initialize the _host field.
        
        @param the_system: The system (hostname or ip) in which the mitigation task
        is being issued to.
        """
        self._host = 'https://' + str(the_system) + self._MGMT_PORT
        
    def _getLWFCreds(self):
        """
        """
        uname = None
        passwd = None
        response, content = splunk.rest.simpleRequest('storage/passwords',
                                    getargs={'output_mode': 'json','count': '0'},
                                    raiseAllErrors=True,
                                    sessionKey=self._localSessionKey)
        
        if response['status'] == "200":
            content = json.loads(content)
            for entry in content['entry']:
                if entry['content']['realm'] == "LWF":
                    uname = entry['content']['username']
                    passwd = entry['content']['clear_password']
                    break
            
            #logger.info("Username: " + str(uname) + " Password: " + str(passwd))
            logger.info("Loggin in as Username: " + str(uname) + " From LWF Realm in cred manager")
        else:
            logger.error("Received something other than an HTTP 200 response " + 
                         "when attempting to acquire the LWF creds from the " + 
                         " cred manager.")
        return uname, passwd

    def _requestSessionKey(self):
        """
        Private Method: _requestSessionKey
            Method used to request a session key from the remote splunk 
            instance.
            
        @return String representation of the session key for the remote splunk
        instance.
        """
        try:
            uname, passwd = self._getLWFCreds()
            url = self._host + self._AUTH_ENDPOINT
            request = urllib2.Request(url,
                data = urllib.urlencode({'username': uname, 'password': passwd,
                    'output_mode': 'json'}))
            content = urllib2.urlopen(request).read()
            content = json.loads(content)
            return 'Splunk ' + content['sessionKey']
        except Exception as e:
            logger.error("There was an issue requesting the session key for " + 
                         " host: " + self._host)
            logger.exception(str(e))
            

    def getSessionKey(self):
        """
        Public Method: getSessionKey
        @return The session key requested from the remote splunk instance.
        """
        return self.sessionKey

    def sendMitigatePIDTask(self, pid):
        """
        Public Method: sendMitigatePIDTask
            Used to issue PID mitigation tasks to the remote splunk instance. 
            
        @param pid: The PID that is to be mitigated by the remote Splunk 
        instance
        """
        try:
            url = self._host + self._SEARCH_ENDPOINT
            request = urllib2.Request(url,
                data = urllib.urlencode({'search': self.queueSearch.format(str(pid), self._time),
                        'output_mode': 'json'}),
                headers = {'Authorization': self.getSessionKey()})
    
            content = urllib2.urlopen(request)
            logger.info("Mitigate PID task sent to host: " + self._host + 
                        " for PID: " + str(pid) + ", at Time: " + self._time)
        except Exception as e:
            logger.error("There was an issue sending a PID Mitigation Task " + 
                         "for host: " + self._host + ", time: " + self._time + 
                         ", PID: " + str(pid)) 
            logger.exception(str(e))

if __name__ == '__main__': 

    try:        
        results, dummyresults, settings = si.getOrganizedResults()
        keywords, options = si.getKeywordsAndOptions()

        for entry in results:
            ## System info
            if "system" in entry:
                system = entry["system"]
            else:
                system = options.get('system', None)

            ## PID Info
            if "pid" in entry:
                pid = entry["pid"]
            else:
                pid = options.get('pid', None)

            mit = Mitigator(system, settings['sessionKey'])
            mit.sendMitigatePIDTask(pid)
            print 'sent PID ' + pid + ' to be mitigated at ' + system 

    except Exception as e:
        logger.error("There was an issue establishing arguments for the " + 
                     "mitigator search command!")
        logger.exception(str(e))
