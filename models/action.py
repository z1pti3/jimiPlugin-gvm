import time

from plugins.gvm.includes import openvas
from plugins.gvm.models import gvmScan

import jimi

class _gvmConnect(jimi.action._action):
	host = str()
	port = 22
	username = str()
	password = str()
	keyFile = str()
	openvasUsername = str()
	openvasPassword = str()
	openvasPort = 9390

	def doAction(self,data):
		host = jimi.helpers.evalString(self.host, {"data" : data["flowData"]})
		username = jimi.helpers.evalString(self.username, {"data" : data["flowData"]})
		if not hasattr(self,"plain_password") and self.password != "":
			self.plain_password = jimi.auth.getPasswordFromENC(self.password)
			password = self.plain_password
		else:
			if self.password != "":
				password = self.plain_password
			else:
				password = None
		keyFile = jimi.helpers.evalString(self.keyFile, {"data" : data["flowData"]})
		openvasUsername = jimi.helpers.evalString(self.openvasUsername, {"data" : data["flowData"]})
		if not hasattr(self,"plain_openvasPassword"):
			self.plain_openvasPassword = jimi.auth.getPasswordFromENC(self.openvasPassword)
		
		if keyFile != "":
			openvasClient = openvas.openvas(host,username,openvasUsername,self.plain_openvasPassword,keyFile=keyFile,keyPassword=password,openvasRemotePort=self.openvasPort,port=self.port)
		else:
			openvasClient = openvas.openvas(host,username,openvasUsername,self.plain_openvasPassword,password=password,openvasRemotePort=self.openvasPort,port=self.port)
		
		if openvasClient != None:
			data["eventData"]["gvm"] = openvasClient
			return {"result" : True, "rc" : 0, "msg" : "Connected."}
		else:
			return {"result" : False, "rc" : 403, "msg" : "Unable to connect."}

	def setAttribute(self,attr,value,sessionData=None):
		if attr == "password" and not value.startswith("ENC "):
			if jimi.db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
				self.password = "ENC {0}".format(jimi.auth.getENCFromPassword(value))
				return True
			return False
		if attr == "openvasPassword" and not value.startswith("ENC "):
			if jimi.db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
				self.openvasPassword = "ENC {0}".format(jimi.auth.getENCFromPassword(value))
				return True
			return False
		return super(_gvmConnect, self).setAttribute(attr,value,sessionData=sessionData)

class _gvmDisconnect(jimi.action._action):

	def doAction(self,data):
		try:
			openvasClient = data["eventData"]["gvm"]
			openvasClient.disconnect()
			return {"result" : True, "rc" : 0, "msg" : "Disconnected."} 
		except KeyError:
			return {"result" : False, "rc" : 404, "msg" : "openvasClient object not found."} 

class _gvmNewScan(jimi.action._action):
	scannerId = str()
	target = str()
	configId = str()
	portListId = str()

	def doAction(self,data):
		if "gvm" in data["flowData"]["plugin"]:
			result = False
			if data["flowData"]["plugin"]["gvm"]["status"] == -100:
				result = True
			return {"result" : result, "rc" : data["flowData"]["plugin"]["gvm"]["status"], "gvm" : data["flowData"]["plugin"]["gvm"], "msg" : "Scan callback."}

		target = jimi.helpers.evalString(self.target, {"data" : data["flowData"]})
		configId = jimi.helpers.evalString(self.configId, {"data" : data["flowData"]})
		portListId = jimi.helpers.evalString(self.portListId, {"data" : data["flowData"]})
		scannerId = jimi.helpers.evalString(self.scannerId, {"data" : data["flowData"]})

		if len(gvmScan._gvmScan().query(query={ "scannerId" : scannerId, "target" : target, "endTime" : -1 })["results"]) > 0:
			return {"result" : False, "rc" : 1, "msg" : "Existing scan for given target still outstanding."}

		scanId = str(gvmScan._gvmScan().new(self.acl,data["flowData"]["conduct_id"],data["flowData"]["flow_id"],target,configId,portListId,scannerId,data).inserted_id)
		return {"result" : True, "rc" : 0, "scan_id" : scanId, "msg" : "New scan created."}

class _gvmGetScan(jimi.action._action):
	scanId = str()

	def doAction(self,data):
		scanId = jimi.helpers.evalString(self.scanId, {"data" : data["flowData"]})
		scan = gvmScan._gvmScan().query(id=scanId)["results"]
		if len(scan) == 1:
			return {"result" : True, "rc" : 0, "scan" : scan[0] }
		return {"result" : False, "rc" : 404, "msg" : "Scan data could not be retrieved."}

class _gvmProcessScans(jimi.action._action):
	scannerId = str()
	scanTimeout = 3600
	maxConcurrent = 3

	def doAction(self,data):
		scannerId = jimi.helpers.evalString(self.scannerId, {"data" : data["flowData"]})

		try:
			openvasClient = data["eventData"]["gvm"]
			canStart = self.maxConcurrent - openvasClient.getScanCount()
			if scanStart < 1:
				jimi.logging.debug("GVM sanner has not slots to start a scan.scannerId={0}".format(scannerId),-1)
			scans = gvmScan._gvmScan().getAsClass(query={ "scannerId" : scannerId, "status" : { "$ne" : 100 }, "endTime" : -1 })
			for scan in scans:
				# New scan
				if scan.status == -1 and canStart > 0:
					createTargetResult = openvasClient.createTarget("Jimi-{0}".format(scan._id),[scan.target],scan.portListId)
					if createTargetResult["@status"] == "201":
						scan.targetId = createTargetResult["@id"]
						createScanResult = openvasClient.createScan("Jimi-{0}".format(scan.target),scan.configId,scan.targetId,scannerId)
						if createScanResult["@status"] != "201":
							jimi.logging.debug("GVM SCan could not be created. target={0}, scannerId={1}".format("Jimi-{0}".format(scan._id),scannerId),-1)
						else:
							openvasClient.startScan(createScanResult["@id"])
							scan.scanId = createScanResult["@id"]
							scan.startTime = int(time.time())
							scan.status = 0
							scan.lastCheck = int(time.time())
							scan.update(["scanId","startTime","status","lastCheck","targetId"])
							canStart -= 1
					else:
						jimi.logging.debug("GVM Target could not be created. target={0}, scannerId={1}".format("Jimi-{0}".format(scan._id),scannerId),-1)
				# Update Scan
				elif scan.status > -1:
					gvmScanResult = openvasClient.getScan(scan.scanId)
					if gvmScanResult["@status"] == "200":
						if gvmScanResult["task"]["status"] == "Done":
							scan.status = 100
							scan.lastCheck = int(time.time())
							scan.endTime = int(time.time())
							scan.reportId = gvmScanResult["task"]["last_report"]["report"]["@id"]

							gvmReport = openvasClient.getReportById(scan.reportId)
							if "result" in gvmReport["report"]["report"]["results"]:
								for gvmReportFinding in gvmReport["report"]["report"]["results"]["result"]:
									finding = {}
									finding["host"] = gvmReportFinding["host"]["#text"]
									finding["port"] = gvmReportFinding["port"]
									finding["threat"] = gvmReportFinding["threat"]
									finding["nvt_family"] = gvmReportFinding["nvt"]["family"]
									finding["css_base"] = gvmReportFinding["nvt"]["cvss_base"]
									tags = gvmReportFinding["nvt"]["tags"].split("|")
									for tag in tags:
										finding[tag.split("=")[0]] = tag.split("=")[1]  
									scan.findings.append(finding)
							scan.update(["status","lastCheck","endTime","reportId","findings"])
							openvasClient.deleteScan(scan.scanId)
							openvasClient.deleteTarget(scan.targetId)
							# Call back to flow_id
							tempData = jimi.conduct.copyData(jimi.conduct.dataTemplate(scan.data,keepEvent=True))
							tempData["flowData"]["callingTriggerID"] = data["flowData"]["trigger_id"]
							tempData["flowData"]["plugin"]["gvm"] = { "status" : 100, "reportData" : scan.findings }
							conduct = jimi.conduct._conduct().getAsClass(id=scan.conductId)[0]
							tempData["flowData"]["eventStats"] = { "first" : True, "current" : 1, "total" : 1, "last" : True }
							jimi.workers.workers.new("trigger:{0}".format(scan._id),conduct.triggerHandler,(scan.flowId,tempData,False,True))
						elif gvmScanResult["task"]["status"] == "Running":
							scan.status = int(gvmScanResult["task"]["progress"])
							scan.lastCheck = int(time.time())
							scan.update(["status","lastCheck"])
						else:
							scan.lastCheck = int(time.time())
							scan.update(["lastCheck"])
						# Error scan has overrun
						if scan.lastCheck - scan.startTime > self.scanTimeout:
							scan.status = -100
							scan.lastCheck = int(time.time())
							scan.endTime = int(time.time())
							scan.update(["status","lastCheck","endTime"])
							openvasClient.stopScan(scan.scanId)
							openvasClient.deleteScan(scan.scanId)
							openvasClient.deleteTarget(scan.targetId)
							# Call back to flow_id
							tempData = jimi.conduct.copyData(jimi.conduct.dataTemplate(scan.data,keepEvent=True))
							tempData["flowData"]["callingTriggerID"] = data["flowData"]["trigger_id"]
							tempData["flowData"]["plugin"]["gvm"] = { "status" : -100 }
							conduct = jimi.conduct._conduct().getAsClass(id=scan.conductID)[0]
							tempData["flowData"]["eventStats"] = { "first" : True, "current" : 1, "total" : 1, "last" : True }
							jimi.workers.workers.new("trigger:{0}".format(scan._id),conduct.triggerHandler,(scan.flowID,tempData,False,True))
					else:
						jimi.logging.debug("GVM Unable to get scan. scanId={0}, scannerId={1}".format("Jimi-{0}".format(scan.scanId),scannerId),-1)

			return {"result" : True, "rc" : 0, "msg" : "Processing Complete."} 
		except KeyError:
			return {"result" : False, "rc" : 404, "msg" : "openvasClient object not found."} 
