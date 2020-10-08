from __future__ import unicode_literals

__doc__ = """

# Copyright 2007 Erik Swan and Splunk, Inc. - erikswan@dogandbone.com
# This file contains a simple imap -> splunk processor
# It is used by splunk to download mail into the splunk server
#
# Change History
# --------------
# Date             Author                Changes
# -----            ------                ---------
# 07/10/2008       Jimmy J       Changes to do the caching by reading the latest UID from splunk messages itself
#                                Code modified to write a UID key/value pair for every message
#                                Removed all commented code
#                                Fixed the function 'usage'
#                                Removed the hard-coded path separator '/', instead used
#                                  os.path.join so it will work even if run on a non *nix platform
#                                Imported traceback module for improved error reporting
#                                Got rid of the splunk CLI interface to determine the last UID
#                                  and used the splunk REST API instead
#                                Got rid of imports that were not being used
#                                Made the splunkHost, splunkuser, splunkpassword and splunkxpassword configurable
#
# 02/11/2014    PJ Balsley       Updated script.
#                                Fixed reading some imap.conf settings that only worked with False/True, and not with 0/1.
#                                Minor typeo fixes.
#                                Minor debug issues fixed.
#
# NOTE: If encrypted passwords are being used, the user needs to run the provided genpass.sh script twice, once for the mailbox password
# and once for the splunk server password. Cut/copy/paste the generated encrypted password and place it into the imap.conf config file
#
"""


import getopt, sys, imaplib, os, email, logging, time
import subprocess, traceback, datetime, io, base64, quopri

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser


def struni(s):
    return s
    '''
    if hasattr(s, "decode"):
        s.decode("ascii", "replace")
    return s
    '''


# Generic error class
class ConfigError(Exception):
    pass

class LoginError(Exception):
    pass

splunk_home = os.getenv('SPLUNK_HOME')
if not splunk_home:
    raise ConfigError('Environment variable SPLUNK_HOME must be set. Run: source ~/bin/setSplunkEnv')

#
# This is the list of configuration options that can be set either on the
# command line or via the imap.conf file.  Note that these names must
# correspond exactly to field names in the IMAPProcessor class and the names
# specified in the optlist near the bottom of this file.
#
# The imap.conf configuration file provides more detailed documentation about
# the effects of each of the options.
#
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
  "timeout",              # seconds to wait for connected to mailserver.
  "noCache",              # if true, the 'already indexed' markers are ignored
  "debug",                # if true, extra debug info is output
  "useSSL",               # true if use ssl
  "deleteWhenDone"        # delete messages after indexing
]

# path to the configuration imap.conf file
scriptDir = sys.path[0] # find it relative to get_imap_email.py file
configDefaultFileName = os.path.join(scriptDir,'..','default','imap.conf')
configLocalFileName = os.path.join(scriptDir,'..','local','imap.conf')

# name of the only stanza in the config file
configSectionName = "IMAP Configuration"


#--------------------------------------------------------------
# IMAPprocessor will download mail from an imap server and write to sdtout.
# This is how to get mail into splunk.
#--------------------------------------------------------------
class IMAPProcessor(object):

    # -------------------
    # default values.
    # -------------------
    def __init__(self):
        # initialize all of the configuration fields with default values that
        # will be used on the off chance that they don't appear in imap.conf
        self.server = ""        # this is required
        self.user = ""          # this is required
        self.password = ""      # and either this...
        self.xpassword = ""     # ...or this is also required
        self.port = 993
        self.folders = 'all'
        self.imapSearch = 'UNDELETED'
        self.fullHeaders = False
        self.includeBody = True
        self.mimeTypes = 'text/plain'
        self._mimeTypesList = []             # split list of mime types
        self.splunkuser = 'admin'
        self.splunkpassword = 'changeme'     # default splunk admin password
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
        self.version = "2.0.5"


    # -----------------------------------
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
                if k.startswith("_"): continue
                logging.debug(k + "=" + str(self.__dict__[k]))
        else:
            logging.basicConfig(level=logging.ERROR)

        # check min required args
        if self.server == "" or self.user == "" or ( self.password == "" and self.xpassword =="" ):
            self.usage()
            #sys.exit()
            raise ConfigError

        # pre-parse the mime types list
        if self.mimeTypes.find(",") > -1:
            self._mimeTypesList = self.mimeTypes.split(",")
        else:
            self._mimeTypesList.append(self.mimeTypes)

        # deleteWhenDone overrides any caching. Our assumption is that all messages in the box are new each time
        if self.deleteWhenDone:
            self.noCache = True

    # -----------------------------------
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
        config = RawConfigParser()
        config.read(path)
        for o in configOptions:
            if config.has_option(configSectionName, o):
                val = getattr(self, o)
                # check to see if the current/default value is a boolean; if so,
                # makes user user supplied value is a bool, will convert string to bool.
                # ie. makes 0 = False and 1 = True
                if isinstance(val, bool):
                    val = (config.get(configSectionName, o).strip().lower() == "true")
                    if config.get(configSectionName, o) == "1":
                        val = True
                    if config.get(configSectionName, o) == "0":
                        val = False
                else:
                    val = config.get(configSectionName, o)
                setattr(self, o, val)


    # ----------------------------------------------------------------
    # Read settings from the command line.  We support command
    # line args mainly for backwards compat and for quick debugging;
    # users should be encouraged to use the imap.conf file instead
    # ----------------------------------------------------------------
    def readOptlist(self, optlist):
        for o, a in optlist:
            o = o[2:] # strip the leading --

            if o in configOptions:
                val = getattr(self, o)
                # check to see if the current/default value is a boolean. If so,
                # then the value is true if specified as a flag; otherwise, convert
                # the option value to a bool.
                if isinstance(val, bool):
                    if (a is None or len(a) == 0) :
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
        logging.debug("Other parameters that can also be supplied. Refer the default/imap.conf file for details")


    # ---------------------------------------------------------
    # Helper function for mapping folder to UID
    # Returns the cached id for the given mailbox, or zero if
    # we've never looked in it before
    # ---------------------------------------------------------
    def getCacheIDForMailbox(self, box):
        if not self.noCache:

                    #If we are here it means we have to extract the last used UID from splunk...
            import splunk.auth as au
            import splunk.search as se
            import splunk
            import httplib2
            import time
            import string

            if self.splunkxpassword:
                try:
                    p = subprocess.Popen('openssl bf -d -a -pass file:"%s"' % (os.path.join(os.environ['SPLUNK_HOME'],'etc','auth', 'splunk.secret')), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                    self.splunkpassword = p.communicate(self.splunkxpassword + '\n')[0]
                except Exception as e:
                    if self.debug:
                        logging.error(e)
                        print(traceback.print_exc(file=sys.stderr))
                    raise ConfigError('Could not decrypt splunkxpassword')

            logging.debug("decrypted splunk password")

            splunk.mergeHostPath(self.splunkHostPath, True)
            try:
                key = au.getSessionKey(self.splunkuser, self.splunkpassword)
            except httplib2.ServerNotFoundError as e:
                raise LoginError("Unable to find the server at %s" % self.splunkHostPath)
            except Exception as e:
                raise LoginError("userid/password combination for splunk user is invalid...")

            if not key:
                raise LoginError("userid/password combination for splunk user is invalid...")

            if box[0] == "'" or box[0] == '"':
                ss = 'search index=mail mailbox=' + box + ' | head 1 | stats max(Date)'
            else:
                ss = 'search index=mail mailbox="' + box + '" | head 1 | stats max(Date)'

            job = se.dispatch(ss, sessionKey=key)

            start = datetime.datetime.now()

            logging.debug("dispatched search = " + ss)
            logging.debug("dispatched job to splunk through the REST API. Waiting for response...")

            while not job.isDone:
                time.sleep(1)
                logging.debug("*** waiting ")
                now = datetime.datetime.now()
                #if (now - start).seconds > self.timeout:
                if int((now - start).seconds) > int(self.timeout):
                    logging.debug("REST response took more than %s seconds, timing out...using default UID of 0 i.e. same as noCache", self.timeout)
                    break


            #if we have caching on, and we run this for the first time, the result will not have any key like UID
            #Hence it will throw a KeyError or IndexError. Just ignore that error and return 0
            try:
                retVal = str(job.results[0]['max(Date)'])
                logging.debug(" got back " + str(retVal))
            except Exception as e:
                logging.debug(str(e))
                logging.debug(" mailbox was empty ")
                retVal = ""

            job.cancel()

            return retVal


        else:
            return ""

    # --------------------------------------------------
    # Method will login and iterate through each folder
    # --------------------------------------------------
    def getMail(self):
        logging.debug("VERSION=%s  (%s)", self.version, sys.version.splitlines()[0])

        # If the user supplied encrypted password then we need to unencrypt.
        if self.xpassword:
            try:
                p = subprocess.Popen('openssl bf -d -a -pass file:"%s"' % (os.path.join(os.environ['SPLUNK_HOME'],'etc','auth', 'splunk.secret')), shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
                self.password = p.communicate(self.xpassword + '\n')[0]
            except Exception as e:
                if self.debug:
                    logging.debug(e)
                    print(traceback.print_exc(file=sys.stderr))
                raise ConfigError('Could not decrypt xpassword')

        # Try and login
        try:
            if self.port:
                if self.useSSL:
                    M = imaplib.IMAP4_SSL(self.server,int(self.port))
                else:
                    M = imaplib.IMAP4(self.server,int(self.port))
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
            raise LoginError('Could not log into server: %s with password provided' % self.server)

        try:
            folder_list = []

            # See if we need to interate all folders put them into a list
            if self.folders.lower() == "all":
                _, list_ = M.list()
                for f in list_[:]:
                    x = f.split()
                    mailbox = " ".join(x[2:])
                    folder_list.append(mailbox)

            # If the user supplied a list of mailboxes, split them up and put in list
            elif not self.folders == "":
                if self.folders.find(",") > -1:
                    folder_list = self.folders.split(",")
                else:
                    folder_list.append(self.folders)
            else:
                folder_list = ["*"]

            # Run though each of the mailboxes
            for i in folder_list:
                self.getMailbox(M, i)

        except LoginError as e:
            if self.debug:
                logging.debug(e)
                print(traceback.print_exc(file=sys.stderr))
            raise e
        except ConfigError as e:
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



    # ---------------------------------------------------
    # Method will login and iterate through each folder.
    # ---------------------------------------------------
    def getMailbox(self, M, box):

        box = box.replace('"/" ', '')
        box = box.strip()
        logging.debug("about to dump mailbox %s" % (box))

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
            logging.debug("using last time of %s", latestTime)

            # Select the mail box at hand, or * for defult
            if box == "*":
                resCode, resText = M.select()
            else:
                resCode, resText = M.select(box)

                try:
                    endid = int(resText[0])
                except ValueError:
                    logging.info("Unable to get end id for box=%s.   Response:  %s", box, resText[0])
                    return
            if endid < 1:
                return

            # each mailbox is its own source. i
            # We use the ***SPLUNK*** header processor trick to change sources for each event
            # each of the below must be on its own line, thus the breaker text after.
            print("***SPLUNK*** source={} sourcetype=imap host={}".format(box, self.server))
            print(self.END_IMAP_BREAKER)

            if latestTime == "":
                self.getAllMail(M, box, endid)
            else:
                self.getLatestMail(latestTime, M, box, endid)

            # if delete when done, clean it up
            if self.deleteWhenDone:
                M.expunge()
            if resCode == 'NO':
                raise ConfigError("Folder name %s does not exist..." % box)

        except Exception as e:
            if self.debug:
                logging.debug(e)
                print(traceback.print_exc(file=sys.stderr))
            logging.exception("ERROR - trying to select mailbox")


        try:
            M.close()
        except:
            pass

    # -------------------------------
    # Download all email
    # ------------------------------
    def getAllMail(self, M, box, endid):

        chunksize = 200
        counter = 1
        logging.debug("about to get all mail up to counter :" + str(endid))

        try:

            while counter <= endid:
                searchStr = "(" + self.imapSearch + " " + str(counter) + ":" + str(counter+chunksize) + ")"
                logging.debug("about so imap search with : " + searchStr)
                counter = counter + chunksize

                _, data = M.search(None, searchStr)
                ids = data[0].split()
                if len(ids) < 1:
                    continue
                logging.debug("returned from search with %d ids", len(ids))
                logging.debug("id return from search : %s", ids)

                # for each message id....
                for num in ids:
                    try:
                        self.fetchMessage(M, box, num, "")
                    except Exception as e:
                        logging.debug("ERROR trying to fetrucn message id: %s", num)
                        if self.debug:
                            logging.debug(e)
                            print(traceback.print_exc(file=sys.stderr))

        except:
            if self.debug:
                print(traceback.print_exc(file=sys.stderr))
            logging.error("ERROR - trying to search mailbox")


    # ---------------------------------------------------
    def getInternalDate(self, M, box, num):
        dstr = ''
        try:
            _, data = M.fetch(num, '(INTERNALDATE)')
            dates = data[0]
            begin = dates.find('"')
            end = dates.rfind('"')
            dstr = dates[begin+1:end]
        except:
            dstr = ''
            logging.debug("ERROR - could not get date for message - this is a problem")

        return dstr


    # ------------------------------------------------------------------
    # get the messages for the day of last time.
    # unfortunately it looks like the granularity of search is per day.
    # so we read starting the day and then skip ahead, kinda lame.
    # ------------------------------------------------------------------
    def getLatestMail( self, latestTimeStr, M, box, endid):
        logging.debug("About to get lastest mail since %s", latestTimeStr)

        # convert to a datetime so we can compare
        lastDateTime = datetime.datetime.strptime(latestTimeStr[:-6],"%d-%b-%Y %H:%M:%S")
        logging.debug("datetime for latest is %s", lastDateTime)

        # strip off the time, since imap only does day granularity
        justDate = latestTimeStr.split(' ')[0]
        searchStr = "(" + self.imapSearch + " SINCE " + justDate + ")"
        logging.debug("About to search IMAP using ; %s", searchStr)
        _, data = M.search(None, searchStr)
        logging.debug("Got back the following for the day %s", data)

        ids = data[0].split()
        logging.debug("returned from search with %d ids", len(ids))
        logging.debug("id return from search : %s", ids)

        # if empty there is no new data, bail.
        if len(ids) < 1:
            logging.debug("Got zero ids, doing nothihng")
            return

        # for each new message id
        for num in ids:
            # get message date so that we can compare to see if is newer
            dstr = self.getInternalDate(M, box, num)
            if dstr == "":
                continue

            # convert message date to datetime so we can compare
            msgDateTime = datetime.datetime.strptime(dstr[:-6],"%d-%b-%Y %H:%M:%S")
            logging.debug("datetime for message %s", msgDateTime)

            # see if we are caught up yet...
            if lastDateTime < msgDateTime:
                # this is a new message, print it out
                self.fetchMessage(M, box, num, dstr)

    # ------------------------------------------------
    # print body message to STDOUT for indexing
    # ------------------------------------------------
    def printBody( self, message, body, cstr ):
        if message.get('Content-Transfer-Encoding', '') == 'base64':
            try:
                body = base64.b64decode(body)
                #cstr.write('decoded base64 successfully' + '\n')
            except ValueError:
                cstr.write('WARNING - could not decode base64' + '\n')
        #pj suggested improvement by vragosta to get rid of occasional " =20" at end of lines.
        #cstr.write(body + '\n')
        cstr.write(quopri.decodestring(body).decode("ascii", "replace") + '\n')

    # -------------------------------------------------
    # Get and print to STDOUT the mail message
    # -------------------------------------------------
    def fetchMessage( self, M, box, num , dstr):
        cstr = io.StringIO()
        try:

            # get UID
            _, data = M.fetch(num, 'UID')
            uid = int(data[0].split()[0])
            lastUID = uid

            if dstr == "":
                dstr = self.getInternalDate(M, box, num)

            # get message body
            try:
                _, data = M.fetch(num, '(BODY.PEEK[])')
                #typ, data = M.fetch(num, '(RFC822)')
                body = data[0][1]
            except Exception as e:
                logging.debug("Fetch error" + num )
                if self.debug:
                    logging.debug(e)
                    print(traceback.print_exc(file=sys.stderr))



            # get message size
            _, data = M.fetch(num, '(RFC822.SIZE)')
            size = data[0].split()
            size = size[-1].replace(')', '')

            # create message object from the body
            message = email.message_from_string(body)

            # Try printing out the date first, we will use this to break the events.
            if dstr == '':
                dstr = 'no date in message'
                for date_attr in ("date", "Date", "DATE"):
                    if date_attr in message:
                        dstr = message[date_attr]
                        break

            cstr.write('Date = "{}"\n'.format(struni(dstr)))

            for k, v in message.items():
                lk = k.lower()
                if lk == 'date':
                    continue
                if not self.fullHeaders:
                    if lk in('from', 'to', 'subject', 'date', 'cc'):
                        cstr.write(k + ' = "' + v.replace('"', '').replace('\n', '').replace('\r', '') + '"\n')
                else:
                    cstr.write(k + ' = "' + v.replace('"', '').replace('\n', '').replace('\r', '') + '"\n')

            # include size and name of folder since they are not part of header
            # interestingly, sometimes these come back quoted - so check.
            if box[0] in ("'", '"'):
                cstr.write('mailbox = {}\n'.format(box))
            else:
                cstr.write('mailbox = "{}"\n'.format(box))

            cstr.write("size = {}\n".format(size))

            # If option includeBody is True then print STOUT the mail body.
            if self.includeBody:
                # print the body separator line.
                cstr.write(self.body_separator + '\n')

                # This option is old and not needed. We auto set sourcetype in inputs.conf now.
                if self.useBodySourceType:
                   # hardcoded the changing of sourcetype to mailbody.
                    # customers can change the procssing of mailbody's differently in props.conf
                    cstr.write("EndIMAPHeader\n")
                    cstr.write("sourcetype={}\n".format(self.bodySourceType))

                    # if we are breaking up the event we need to spit out a timestamp.
                    cstr.write("date = {}\n".format(message['date']))


                # if the message is not multipart - its text so just dump it out.
                #for key in message.keys():
                #       cstr.write("***key " + key + "  ** value=" + message.get(key)+ '\n')
                if not message.is_multipart():
                    body = message.get_payload()
                    self.printBody(message, body, cstr)
                else:
                    # if it is multipart, then only dump parts whose type is
                    # in the mimeTypes list.
                    for part in message.walk():
                        if part.get_content_type() in self._mimeTypesList:
                            body = part.get_payload(decode=True)
                            self.printBody( message, body, cstr )
            # else, we are not indexing the message body, so do nothing.
            # just print debug data only.
            else:
                if self.debug:
                    for part in message.walk():
                        cstr.write("ContentType :       {}\n".format(part.get_content_type()))
                        logging.debug("No message context to print as value includeBody is set to False")

            cstr.write(self.END_IMAP_BREAKER)

            if self.useBodySourceType:
                # set us back to mail sourcetype
                cstr.write("***splunk*** sourcetype={}\n".format(self.headerSourceType))

            # Write event to splunk
            print(cstr.getvalue())

            # if delete when done, then mark the message
            if self.deleteWhenDone:
                M.store(num, '+Flags', r'(\Deleted)')


        except Exception as e:
            logging.debug("1. Failed to get and print message with UID " + num )
            if self.debug:
                logging.debug(e)
                print(traceback.print_exc(file=sys.stderr))
            logging.debug("2. Failed to get and print message with UID " + num )


# --------------------------------------------------------------
# - parse all program options
# --------------------------------------------------------------
def parseArgs():
    imapProc = IMAPProcessor()

    optlist = None
    try:
        optlist, args = getopt.getopt(sys.argv[1:], '?',['version', 'server=','user=', 'password=', 'xpassword=', 'port=', 'folders=', 'imapSearch=', 'fullHeaders=', 'includeBody=', 'mimeTypes=', 'splunkuser=', 'splunkpassword=', 'splunkxpassword=', 'splunkHostPath=', 'timeout=', 'noCache', 'debug', 'useSSL=', 'deleteWhenDone='])
        if 'version' in args:
            print(sys.argv[0], "version =",  str(imapProc.version))
            return
        imapProc.initFromOptlist(optlist)
    except getopt.error as val:
        logging.error("val=%s # tell them what was wrong", val)
        imapProc.usage()
        raise ConfigError("Incorrect usage...")

    #- Do the work....
    imapProc.getMail()


# --------------------------------------------------------------
# - Start script
# --------------------------------------------------------------
if __name__ == '__main__':

    parseArgs()
