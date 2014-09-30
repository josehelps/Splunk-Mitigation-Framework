import logging
import logging.handlers
import subprocess

import splunk.Intersplunk as si
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

## Setup the logger
def setup_logger():
    """
    Sets up a logger for the ProcMitigator.
    """
    
    logger = logging.getLogger('proc_mitigator')
    # Prevent the log messages from being duplicated in the python.log
    #    Authorization Failed
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    
    file_handler = logging.handlers.RotatingFileHandler(
                        make_splunkhome_path(['etc', 'apps', 'SA-LWF-Mitigation',
                                              'logs','proc_mitigator.log']))
    
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    file_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logger()

class ProcMitigator(object):
    """
    Process Mitigator Class
        Used to Mitigate, kill, processes found in the Process Mitigation 
        Queue (proc_mitigation_queue).
    """
    
    ## Mitigate PID Command dictionary
    _proc_cmds = {
        "kill_pid": {
            'win': ['taskkill', '/F', '/PID'],
            'nix': ['kill', '-9']
        },
        "kill_proc_name": {
            'win': ['taskkill', '/F' ,'/IM'],
            'nix': ['killall', '-9'],
        },
        "list_procs": {
            'win': ['tasklist', '/V', '/FO', 'CSV'],
            'nix': ['ps', '-A', '-o', 'pid']
        }
    }

    def __init__(self, platform):
        """
        ProcMitigator Constructor
            Used to initialize the Process Mitigator
        @param platform: The O/S platform of the system running the mitigator
        app. This MUST be one of [win, nix]. 
        """
        self._setPlatform(platform)
        if self._platform is not None:
            logger.info("ProcMitigator established for platform: " + 
                        self._platform)

    def _setPlatform(self, platform):
        """
        Private method: _setPlatform
            Used to initialize the _platform field.
        @param platform: The O/S platform of the system running the mitigator
        app. This MUST be one of [win, nix]. 
        """
        if platform in ['win', 'nix']:
            self._platform = platform
        else:
            logger.error("Unknown Platform Used! - Specified Platform: " + 
                         str(self._platform))
            self._platform = None

    def getPlatform(self):
        """
        Public Method: getPlatform
        @return: <tt>self._platform</tt>
        """
        return self._platform

    def _generateWinProcListing(self):
        """
        Private Method: _generateWinProcList
        @return: A List of processes currently running on the system. Assumes
        the O/S platform is windows.
        """
        p = subprocess.Popen(self._proc_cmds['list_procs']['win'],
            stdout=subprocess.PIPE)
        out, err = p.communicate()

        proc_list = []
        out = out.split('\n')
        header = out[0]
        header = header[1:-1].split('","')
        out = out[1:]
        if not out[-1]:
            out = out[:-1]
        for line in out:
            attribs = line[1:-1].split('","')
            temp = {}
            for i in range(len(attribs)):
                temp[header[i]] = attribs[i]
            proc_list.append(temp)
        logger.info("Windows Process Listing Generated!")
        return proc_list


    def _generateNixProcListing(self):
        """
        Private Method: _generateNixProcListing
        @return: A list of processes currently running on the system. Assumes
        the O/S platform is Nix based.
        """
        p = subprocess.Popen(self._proc_cmds['list_procs']['nix'],
            stdout=subprocess.PIPE)
        out, err = p.communicate()

        proc_list = []
        out = out.split('\n')
        header = out[0].strip()
        out = out[1:]
        if not out[-1]:
            out = out[:-1]
        for line in out:
            line = line.strip()
            proc_list.append({header: line})
        logger.info("Nix Process Listing Generated!")
        return proc_list


    def locateProcess(self, proc_name=None, pid=None):
        """
        Public Method: locateProcess
        @return: <tt>True</tt> if proc_name or pid were found in the process 
        listing, <tt>False</tt> otherwise.
        """
        located = False
        if self.getPlatform() == 'win':
            proc_list = self._generateWinProcListing()
            for proc in proc_list:
                if proc_name == proc['Image Name']:
                    located = True
                    break
                elif pid == proc['PID']:
                    located = True
                    break
        elif self.getPlatform() == 'nix':
            proc_list = self._generateNixProcListing()
            for proc in proc_list:
                if pid == proc['PID']:
                    located = True
                    break

        return located

    def killProcByID(self, the_pid):
        """
        Public Method: killProcByID
            Used to issue a kill pid command to the system to for 
            <tt>the_pid</tt>.
            
        @param the_pid: The PID of the process to be killed.
        @return <tt>[out, err]</tt> from the process communication.
        """
        out = None
        err = None
        if self.locateProcess(pid=the_pid):
            p = subprocess.Popen(self._proc_cmds['kill_pid'][self.getPlatform()] + [str(the_pid)], 
                stdout=subprocess.PIPE)
            out, err = p.communicate()
        else:
            logger.error("PID: " + str(the_pid) + " not found running on " + 
                         "the system!")
        return [out,err]

    def killProcByName(self, the_proc_name):
        """
        Public Method: killProcByName
            Used to issue a kill process command to the system for 
            <tt>the_proc_name</tt>
            
        @param the_proc_name: The Process Name of the process to be killed.
        @return <tt>[out, err]</tt> from the process communication. 
        """
        out = None
        err = None
        if self.locateProcess(proc_name=the_proc_name):
            p = subprocess.Popen(self._proc_cmds['kill_proc_name'][self.getPlatform()] + [str(the_proc_name)], 
                stdout=subprocess.PIPE)
            out, err = p.communicate()
        else:
            logger.error("Process Name: " + str(the_proc_name) + " not found " + 
                         " running on the system!")

        return [out,err]

if __name__ == '__main__': 
    try:
        results = si.readResults()
        keywords, options = si.getKeywordsAndOptions()
        
        for entry in results:
            ## PID
            if "pid" in entry:
                pid = entry["pid"]
            else:
                pid = options.get('pid', None)
                
            ## Process Name
            if 'proc_name' in entry:
                proc_name = entry['proc_name']
            else:
                proc_name = options.get('proc_name', None)
                
            ## Platform
            if 'platform' in entry:
                platform = entry['platform']
            else:
                platform = options.get('platform', None)
                
            mitigator = ProcMitigator(str(platform))

            if pid is not None:
                logger.info(str(mitigator.killProcByID(str(pid))))
            elif proc_name is not None:
                logger.info(str(mitigator.killProcByName(str(proc_name))))

    except Exception as e:
        logger.error("There was an issue establishing arguments fro the " + 
                     "mitigateProc search command!")
        logger.exception(str(e))
