import getopt, sys, imaplib, os, string, email, logging, time, datetime
import subprocess, configparser, traceback, datetime, io, base64, quopri,getopt
import splunk.auth as au
import splunk.search as se
import splunk
import httplib2

from io import StringIO

# Generic error class
class ConfigError(Exception):
    pass

class LoginError(Exception):
    pass

splunk_home = os.getenv('SPLUNK_HOME')
if not splunk_home:
    raise ConfigError('Environment variable SPLUNK_HOME must be set. Run: source ~/bin/setSplunkEnv')

configOptions = [ 
    "server",               # imap server name/ip
    "user",                 # imap user account
    "password",             # imap plaintext password
    "xpassword",            # or imap encrypted password
    "port",                 # imap server port
    "folders",              # list of imap folders to index
    "imapSearch",           # imap search string
    "fullHeaders",          # whether all headers should be indexed
    "includeBody",          # whether the body of messages should be indexed
    "mimeTypes",            # list of mime types to index if multipart
    "splunkuser",           # splunk server userid
    "splunkpassword",       # splunk server password
    "splunkxpassword",      # or splunk server encrypted password 
    "splunkHostPath",       # splunk server host path
    "timeout",              # seconds to wait for connection to mailserver
    "noCache",              # if true, the 'already indexed' markers are ignored
    "debug",                # if true, extra debug info is output
    "useSSL",               # true if use SSL
    "deleteWhenDone"        # delete messages after indexing
]

scriptDir = sys.path[0]  # find it relative to the get_imap_email.py file
configDefaultFileName = os.path.join(scriptDir, '..', 'default', 'imap.conf')
configLocalFileName = os.path.join(scriptDir, '..', 'local', 'imap.conf')

# name of the only stanza in the config file
configSectionName = "IMAP Configuration"

class IMAPProcessor(object):

    # -------------------
    # default values.
    # -------------------
    def __init__(self):
        # initialize all of the configuration fields with default values that
        # will be used on the off chance that they don't appear in imap.conf
        self.server = ""  # this is required
        self.user = ""  # this is required
        self.password = ""  # and either this...
        self.xpassword = ""  # ...or this is also required
        self.port = 993
        self.folders = 'all'
        self.imapSearch = 'UNDELETED'
        self.fullHeaders = False
        self.includeBody = True
        self.mimeTypes = 'text/plain'
        self._mimeTypesList = []  # split list of mime types
        self.splunkuser = 'admin'
        self.splunkpassword = 'changeme'  # default splunk admin password
        self.splunkxpassword = ''
        self.splunkHostPath = 'https://localhost:8089'
        self.timeout = 10
        self.noCache = False
        self.debug = False
        self.useSSL = True
        self.deleteWhenDone = False
        self.END_IMAP_BREAKER = 'EndIMAPMessage'
        self.bodySourceType = 'imapbody'
        self.body_separator = '____________________  Message Body  ____________________'
        self.headerSourceType = 'imap'
        self.useBodySourceType = False
        self.version = "2.0"

            # read in all options and settings.
    # -----------------------------------
    def initFromOptlist(self, optlist):
        # First read settings in imap.conf, if it exists...
        self.readConfig()

        # ...now, for debugging and backward compat, allow command line 
        # settings to override...
        self.readOptlist(optlist)
 
        if self.debug:
            logging.basicConfig(level=logging.DEBUG)
            keys = sorted(self.__dict__.keys())
            for k in keys:
                if k.startswith("_"):
                    continue
                logging.debug(f"{k}={str(self.__dict__[k])}")
        else:
            logging.basicConfig(level=logging.ERROR)

        # check min required args
        if self.server == "" or self.user == "" or (self.password == "" and self.xpassword == ""):
            self.usage()
            raise ConfigError

        # pre-parse the mime types list
        if "," in self.mimeTypes:
            self._mimeTypesList = self.mimeTypes.split(",")
        else:
            self._mimeTypesList.append(self.mimeTypes)

        # deleteWhenDone overrides any caching. Our assumption is that all messages in the box are new each time
        if self.deleteWhenDone:
            self.noCache = True

            # - Read settings from imap.conf(s) 
    # -----------------------------------
    def readConfig(self):
        path = ''
        if os.path.exists(configLocalFileName):
            path = configLocalFileName
        elif os.path.exists(configDefaultFileName):
            path = configDefaultFileName
        else:
            return

        config = configparser.RawConfigParser()
        config.read(path)
        
        for o in configOptions:
            if config.has_option(configSectionName, o):
                val = getattr(self, o)
                
                # Check if the current/default value is a boolean
                if isinstance(val, bool):
                    option_value = config.get(configSectionName, o).strip().lower()
                    if option_value in ["true", "1"]:
                        val = True
                    elif option_value in ["false", "0"]:
                        val = False
                else:
                    val = config.get(configSectionName, o)
                
                setattr(self, o, val)

                 # ----------------------------------------------------------------
    # Read settings from the command line. We support command
    # line args mainly for backwards compatibility and for quick debugging;
    # users should be encouraged to use the imap.conf file instead
    # ----------------------------------------------------------------
    def readOptlist(self, optlist):
        for o, a in optlist:
            o = o[2:]  # strip the leading --

            if o in configOptions:
                val = getattr(self, o)
                
                # Check if the current/default value is a boolean.
                if isinstance(val, bool):
                    if a is None or len(a) == 0:
                        val = True
                    else:
                        val = (a.strip().lower() == "true")
                else:
                    val = a
                
                setattr(self, o, val)

                 # ---------------------
    # usage text for help
    # ---------------------
    def usage(self):
        
        logging.debug("The required fields are: server, user and (password or xpassword)")
        logging.debug("eg:")
        logging.debug("python get_imap_email.py --server=<mail server name> --user=<user name> --password=<unencrypted password> OR")
        logging.debug("python get_imap_email.py --server=<mail server name> --user=<user name> --xpassword=<encrypted password>")
        logging.debug("Other parameters that can also be supplied. Refer to the default/imap.conf file for details")


           # Helper function for mapping folder to UID
    # Returns the cached id for the given mailbox, or zero if
    # we've never looked in it before
    # ---------------------------------------------------------
    def getCacheIDForMailbox(self, box):
        if not self.noCache:
           
        
    # If we are here it means we have to extract the last used UID from Splunk...
            if self.splunkxpassword:
                try:
                    p = subprocess.Popen(
                        ['openssl', 'bf', '-d', '-a', '-pass', f'file:{os.path.join(os.environ["SPLUNK_HOME"], "etc", "auth", "splunk.secret")}'],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    self.splunkpassword, _ = p.communicate(input=(self.splunkxpassword + '\n').encode())
                    self.splunkpassword = self.splunkpassword.decode().strip()
                except Exception as e:
                    if self.debug:
                        logging.error(e)
                        traceback.print_exc(file=sys.stderr)
                    raise ConfigError('Could not decrypt splunkxpassword')

            logging.debug("Decrypted Splunk password")
            
            splunk.mergeHostPath(self.splunkHostPath, True)
            try:
                key = au.getSessionKey(self.splunkuser, self.splunkpassword)
            except httplib2.ServerNotFoundError as e:
                raise LoginError(f"Unable to find the server at {self.splunkHostPath}")
            except Exception as e:
                raise LoginError("UserID/password combination for Splunk user is invalid...")

            if not key:
                raise LoginError("UserID/password combination for Splunk user is invalid...")

            if box[0] in ["'", '"']:
                ss = f'search index=mail mailbox={box} | head 1 | stats max(Date)'
            else:
                ss = f'search index=mail mailbox="{box}" | head 1 | stats max(Date)'

            job = se.dispatch(ss, sessionKey=key)

            start = datetime.datetime.now()

            logging.debug(f"Dispatched search = {ss}")
            logging.debug("Dispatched job to Splunk through the REST API. Waiting for response...")

            while not job.isDone:
                time.sleep(1)
                logging.debug("*** waiting ")
                now = datetime.datetime.now()
                if int((now - start).seconds) > int(self.timeout):
                    logging.debug(f"REST response took more than {self.timeout} seconds, timing out...using default UID of 0 i.e. same as noCache")
                    break

            try:
                retVal = str(job.results[0]['max(Date)'])
                logging.debug(f"Got back {retVal}")
            except (KeyError, IndexError, Exception) as e:
                logging.debug(str(e))
                logging.debug("Mailbox was empty")
                retVal = "" 

            job.cancel()

            return retVal
        else:
            return ""

              # --------------------------------------------------
    # Method will login and iterate through each folder 
    # --------------------------------------------------
    def getMail(self):
        logging.debug("VERSION = " + str(self.version))
    
        # If the user supplied an encrypted password, we need to decrypt it.
        if self.xpassword:
            try:
                p = subprocess.Popen(
                    ['openssl', 'bf', '-d', '-a', '-pass', f'file:{os.path.join(os.environ["SPLUNK_HOME"], "etc", "auth", "splunk.secret")}'],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                self.password, _ = p.communicate(input=(self.xpassword + '\n').encode())
                self.password = self.password.decode().strip()
            except Exception as e:
                if self.debug:
                    logging.debug(e)
                    print(traceback.print_exc(file=sys.stderr))
                raise ConfigError('Could not decrypt xpassword')

        # Try and login
        try:
            if self.port:
                if self.useSSL:
                    M = imaplib.IMAP4_SSL(self.server, int(self.port))
                else:
                    M = imaplib.IMAP4(self.server, int(self.port))
            else:
                if self.useSSL:
                    M = imaplib.IMAP4_SSL(self.server)
                else:
                    M = imaplib.IMAP4(self.server)
                    
            M.login(self.user, self.password)
        except Exception as e:
            if self.debug:
                logging.debug(e)
                print(traceback.print_exc(file=sys.stderr))
            raise LoginError(f'Could not log into server: {self.server} with the password provided')

        try:       
            folder_list = []
      
            # See if we need to iterate all folders, put them into a list
            if self.folders.lower() == "all":
                result, data = M.list()
                for f in data:
                    x = f.split()
                    mailbox = b" ".join(x[2:]).decode()
                    folder_list.append(mailbox)
          
            # If the user supplied a list of mailboxes, split them up and put in a list
            elif self.folders:
                if "," in self.folders:
                    folder_list = self.folders.split(",")
                else:
                    folder_list.append(self.folders)
            else:
                folder_list = ["*"]
         
            # Run through each of the mailboxes
            for i in folder_list:
                self.getMailbox(M, i)

        except (LoginError, ConfigError) as e:
            if self.debug:
                logging.debug(e)
                print(traceback.print_exc(file=sys.stderr))
            M.logout()
            raise e
        except Exception as e:          
            if self.debug:
                logging.debug(e)
                print(traceback.print_exc(file=sys.stderr))
            logging.error("ERROR - trying to login to server and get folders")
        finally:
            M.logout()

            # Method will login and iterate through each folder.
    # ---------------------------------------------------
    def getMailbox(self, M, box):
        box = box.replace('"/" ', '').strip()
        logging.debug(f"About to dump mailbox \"{box}\"")

        # new method
        # search for the last internal time
        # get messages since that day of the latest internal time
        # get internal time for each message
        # skip ahead until the internal time is matching
        # dedupe
        # for all new messages index.

        try:
            # get message id we read up to last time (0 first time)
            latestTime = self.getCacheIDForMailbox(box)
            logging.debug(f"Using last time of {latestTime}")

            # Select the mail box at hand, or * for default
            if box == "*":
                resCode, resText = M.select()
            else:
                resCode, resText = M.select(box)
       
            if resCode == 'NO':
               raise ConfigError(f"Folder name {box} does not exist...")
            
            endid = int(resText[0])
            if endid < 1:
                return

            # each mailbox is its own source.
            # We use the ***SPLUNK*** header processor trick to change sources for each event
            # each of the below must be on its own line, thus the breaker text after.
            print(f"***SPLUNK*** source={box} sourcetype=imap host={self.server}")
            print(self.END_IMAP_BREAKER)

            if latestTime == "":
                self.getAllMail(M, box, endid)
            else:
                self.getLatestMail(latestTime, M, box, endid)

            # if delete when done, clean it up
            if self.deleteWhenDone:
                M.expunge()
            if resCode == 'NO':
                raise ConfigError(f"Folder name {box} does not exist...")

        except Exception as e:
            if self.debug:
                logging.debug(e)
                print(traceback.format_exc(), file=sys.stderr)
            logging.error("ERROR - trying to select mailbox")

        try:
            M.close()
        except Exception as e:
            logging.debug(f"Error closing mailbox: {e}")

             # Download all email
    # ------------------------------
    def getAllMail(self, M, box, endid):

        chunksize = 200
        counter = 1
        logging.debug(f"About to get all mail up to counter: {endid}")

        try:
            while counter <= endid:
                searchStr = f"({self.imapSearch} {counter}:{counter+chunksize})"
                logging.debug(f"About to IMAP search with: {searchStr}")
                counter += chunksize

                typ, data = M.search(None, searchStr)
                ids = data[0].split()
                if len(ids) < 1:
                    continue
                logging.debug(f"Returned from search with {len(ids)} ids")
                logging.debug(f"ID returned from search: {ids}")

                # For each message id...
                for num in ids:
                    try:
                        self.fetchMessage(M, box, num.decode(), "")
                    except Exception as e:
                        logging.debug(f"ERROR trying to fetch message id: {num.decode()}")
                        if self.debug:
                            logging.debug(e)
                            print(traceback.format_exc(file=sys.stderr))

        except Exception as e:
            if self.debug:
                print(traceback.format_exc(file=sys.stderr))
            logging.error("ERROR - trying to search mailbox")

              # ---------------------------------------------------
    def getInternalDate(self, M, box, num):
        dstr = ''
        try:
            typ, data = M.fetch(num, '(INTERNALDATE)')
            dates = data[0].decode()  # Decode byte string to string
            begin = dates.find('"')
            end = dates.rfind('"')
            dstr = dates[begin+1:end]
        except Exception as e:
            dstr = ''
            logging.debug("ERROR - could not get date for message - this is a problem")
            logging.debug(e)

        return dstr

           # ------------------------------------------------------------------
    # get the messages for the day of last time.
    # unfortunately it looks like the granularity of search is per day.
    # so we read starting the day and then skip ahead, kinda lame.
    # ------------------------------------------------------------------
    def getLatestMail(self, latestTimeStr, M, box, endid):
        logging.debug(f"About to get latest mail since {latestTimeStr}")

        # Convert to a datetime so we can compare
        lastDateTime = datetime.datetime.strptime(latestTimeStr[:-6], "%d-%b-%Y %H:%M:%S")
        logging.debug(f"Datetime for latest is {lastDateTime}")

        # Strip off the time, since IMAP only does day granularity
        justDate = latestTimeStr.split(' ')[0]
        searchStr = f"({self.imapSearch} SINCE {justDate})"
        logging.debug(f"About to search IMAP using: {searchStr}")
        typ, data = M.search(None, searchStr)
        logging.debug(f"Got back the following for the day: {data}")

        ids = data[0].split()
        logging.debug(f"Returned from search with {len(ids)} ids")
        logging.debug(f"ID returned from search: {ids}")

        # If empty there is no new data, bail.
        if len(ids) < 1:
            logging.debug("Got zero ids, doing nothing")
            return

        # For each new message id
        for num in ids:
            # Get message date so that we can compare to see if it is newer 
            dstr = self.getInternalDate(M, box, num.decode())
            if dstr == "":
                continue

            # Convert message date to datetime so we can compare
            msgDateTime = datetime.datetime.strptime(dstr[:-6], "%d-%b-%Y %H:%M:%S")
            logging.debug(f"Datetime for message: {msgDateTime}")

            # See if we are caught up yet...
            if lastDateTime < msgDateTime:
                # This is a new message, process it
                self.fetchMessage(M, box, num.decode(), dstr)
    # ---------------------------------------------------
    # print body message to STDOUT for indexing
    # ---------------------------------------------------
    def printBody(self, message, body, cstr):
        if 'Content-Transfer-Encoding' in message and message.get('Content-Transfer-Encoding') == 'base64':
            try:
                body = base64.b64decode(body)
            except Exception as e:
                cstr.write('WARNING - could not decode base64\n')
        
        cstr.write(quopri.decodestring(body).decode() + '\n')

    # -------------------------------------------------
    # Get and print to STDOUT the mail message
    # -------------------------------------------------
    def fetchMessage(self, M, box, num, dstr):
        cstr = StringIO()
        try:
            # get UID
            typ, data = M.fetch(num, 'UID')
            uid = int(data[0].split()[0])
            lastUID = uid

            if dstr == "":
                dstr = self.getInternalDate(M, box, num)

            # get message body
            try:
                typ, data = M.fetch(num, '(BODY.PEEK[])')
                body = data[0][1]
            except Exception as e:
                logging.debug(f"Fetch error {num}")
                if self.debug:
                    logging.debug(e)
                    print(traceback.format_exc(), file=sys.stderr)

            # get message size
            typ, data = M.fetch(num, '(RFC822.SIZE)')
            # Decode bytes to string
            size_str = data[0].decode().split()[-1].replace(')', '')
            size = int(size_str)

            # create message object from the body
            message = email.message_from_bytes(body)

            # Try printing out the date first, we will use this to break the events.
            if dstr == '':
                dstr = 'no date in message'
                if 'date' in message:
                    dstr = message['date']
                elif 'Date' in message:
                    dstr = message['Date']
                elif 'DATE' in message:
                    dstr = message['DATE']

            cstr.write(f'Date = "{dstr}"\n')

            for k, v in message.items():
                if k.lower() in ['date']:
                    continue
                if not self.fullHeaders:
                    lk = k.lower()
                    if lk in ['from', 'to', 'subject', 'date', 'cc']:
                        cstr.write('{} = "{}"\n'.format(k, v.replace('"', '')))
                else:
                    cstr.write('{} = "{}"\n'.format(k, v.replace('"', '')))

            # include size and name of folder since they are not part of header
            if box[0] in ["'", '"']:
                cstr.write(f'mailbox = {box}\n')
            else:
                cstr.write(f'mailbox = "{box}"\n')

            cstr.write(f"size = {size}\n")

            # If option includeBody is True then print STDOUT the mail body.
            if self.includeBody:
                # print the body separator line.
                cstr.write(self.body_separator + '\n')

                if self.useBodySourceType:
                    # Hardcoded the changing of sourcetype to mailbody.
                    cstr.write("EndIMAPHeader\n")
                    cstr.write(f"sourcetype={self.bodySourceType}\n")
              
                    # If we are breaking up the event we need to spit out a timestamp.
                    cstr.write(f"date = {message['date']}\n")

                # If the message is not multipart - it's text so just dump it out.
                if not message.is_multipart():
                    body = message.get_payload()
                    self.printBody(message, body, cstr)
                else:
                    # If it is multipart, then only dump parts whose type is in the mimeTypes list.
                    for part in message.walk():
                        if part.get_content_type() in self._mimeTypesList:
                            body = part.get_payload(decode=True)
                            self.printBody(message, body, cstr)
            else:
                if self.debug:
                    for part in message.walk():
                        cstr.write(f"ContentType : {part.get_content_type()}\n")
                    logging.debug("No message context to print as value includeBody is set to False\n")

            cstr.write(self.END_IMAP_BREAKER)

            if self.useBodySourceType:
                # Set us back to mail sourcetype
                cstr.write(f"***splunk*** sourcetype={self.headerSourceType}\n")
            
            print(cstr.getvalue())

            # If delete when done, then mark the message
            if self.deleteWhenDone:
                M.store(num, '+Flags', '(\Deleted)')

        except Exception as e:
            logging.debug(f"1. Failed to get and print message with UID {num}: {e}")
            if self.debug:
                logging.debug(e)
                print(traceback.format_exc(), file=sys.stderr)
            logging.debug(f"2. Failed to get and print message with UID {num}")

# --------------------------------------------------------------
# - parse all program options
# --------------------------------------------------------------
def parseArgs():
    imapProc = IMAPProcessor()

    optlist = None
    try:
        optlist, args = getopt.getopt(sys.argv[1:], '?', [
            'version', 'server=', 'user=', 'password=', 'xpassword=', 
            'port=', 'folders=', 'imapSearch=', 'fullHeaders=', 
            'includeBody=', 'mimeTypes=', 'splunkuser=', 'splunkpassword=', 
            'splunkxpassword=', 'splunkHostPath=', 'timeout=', 'noCache', 
            'debug', 'useSSL=', 'deleteWhenDone='
        ])
        if 'version' in args:
            print(sys.argv[0], "version =", str(imapProc.version))
            return
        imapProc.initFromOptlist(optlist)
    except getopt.GetoptError as val:
        logging.error(str(val))
        imapProc.usage()
        raise ConfigError("Incorrect usage...")
    
    # Do the work...
    imapProc.getMail()

# --------------------------------------------------------------
# - Start script
# --------------------------------------------------------------
if __name__ == '__main__':
    parseArgs()