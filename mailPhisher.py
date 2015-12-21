#python imports
import sys
import imaplib
import getpass
import email
import email.header
import datetime
from threading import Timer
from email.parser import HeaderParser
import urllib

#burp imports
from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue

#java imports
from java.net import URL

#constants
IMAP_HOST = "imap.mail.yahoo.com"
EMAIL_ACCOUNT = "wishiwasreal@yahoo.com"
EMAIL_PASS = "dontguessmeplease"
EMAIL_FOLDER = "Inbox"
PAYLOAD = "<h1>HGSHG</h1>"

#globals
callbacks = None
helpers = None



class BurpExtender(IBurpExtender,IHttpListener):
	def registerExtenderCallbacks(self,this_callbacks):
		global callbacks,helpers

		#register callback and helper
		callbacks = this_callbacks
		helpers = callbacks.getHelpers()
		

		#set extension name
		callbacks.setExtensionName("MailPhisher")
		
		#register ourselves as http listener so we can see requests
		callbacks.registerHttpListener(self)

		return
	

	def checkVuln(self,msgInfo,pl):
		print "inside check for vuln\n"
		self.email = EmailReader(IMAP_HOST,EMAIL_ACCOUNT,EMAIL_PASS)
		self.email.connect()
		self.email.checkMail(msgInfo,pl)


	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		#print "checking urlencoded3 " + urllib.quote_plus(PAYLOAD) + " in " + helpers.bytesToString(messageInfo.getRequest()) + "\n"
		if messageIsRequest:
			if PAYLOAD in helpers.bytesToString(messageInfo.getRequest()) or urllib.quote_plus(PAYLOAD) in helpers.bytesToString(messageInfo.getRequest()):
				print "checking for vuln\n"
				Timer(30.0, self.checkVuln,[messageInfo,PAYLOAD]).start()
		return


class EmailReader():
	def __init__(self,imapHost,email_acc,email_pass,folder = "Inbox",isSSL = True):
		self.imapHost = imapHost
		self.isSSL = isSSL
		self.email_acc = email_acc
		self.email_pass = email_pass
		self.folder = folder
		self.M = None

	def connect(self):
		#check if ssl is set
		if(self.isSSL):
			self.M = imaplib.IMAP4_SSL(self.imapHost)
		else:
			self.M = imaplib.IMAP4(self.imapHost)
		
		#login to account
		try:
			rv, data = self.M.login(self.email_acc, self.email_pass)
			if rv == 'OK':
				print "Logged in."
		except imaplib.IMAP4.error:
			print "LOGIN FAILED!!!"

		#select folder
		rv, mailboxes = self.M.list()
		if rv == 'OK':
			if self.isMailBoxPresent(mailboxes,self.folder):
				print "Found mailbox " + self.folder
				rv, data = self.M.select(self.folder)
				if rv != 'OK':
					print "Failed to select mailbox! Please try again"
		else:
			print "Mailbox " + self.folder + " not found!"

	def isMailBoxPresent(self,mailbox,folder):
		for i in mailbox:
			if folder in i:
				return True
		return False

	def checkMail(self,burpMessage,payload):
		rv, data = self.M.search(None, "ALL")
		if rv != 'OK':
			print "No messages found!"
			return
		#print "dat alen is " + str(len(data))
		msgs = data[0].split()
		msgs.reverse()

		for i in msgs:
			typ, data = self.M.fetch(i, '(RFC822)')
			body = str(email.message_from_string(data[0][1]))
			#print "checking in " + body + " \n"
			#body_start_offset = body.find("Content-Type: text/html;")
			#body = body[body_start_offset:]
			res = body.find(payload)
			if(res == -1):
				print "not vuln"
			else:
				print "VULN!!"
				myURL = helpers.analyzeRequest(burpMessage.getHttpService(),burpMessage.getRequest()).getUrl()
				callbacks.addScanIssue(CustomScanIssue(burpMessage.getHttpService(),myURL,[burpMessage],"Email Content Injection","An Email Content Injection has been detected whereby un-escaped html data is copied into the email body. These emails usually are sent from someemail@targetdomain.com and therefore can be used for genuine pishing attacks. The attacker can abuse this issue to send phishing emails (for example: change your password at evil.com) which appear to come from the target domain and therefore will be considered legitimate from the victim." ,"Tentative","Medium"))
				break
		self.M.close()

	def logout(self):
		self.M.logout



class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        self.HttpService = httpService
        self.Url = url
        self.HttpMessages = httpMessages
        self.Name = name
        self.Detail = detail
        self.Severity = severity
        self.Confidence = confidence
        print "Reported: " + name + " on " + str(url)
        return

    def getUrl(self):
        return self.Url

    def getIssueName(self):
        return self.Name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self.Severity

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self.Detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService