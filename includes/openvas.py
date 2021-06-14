from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from xml.etree import ElementTree
from sshtunnel import SSHTunnelForwarder
from pathlib import Path
import xmltodict
import json

class openvas():

    def __init__(self,host,username,openvasUsername,openvasPassword,port=22,openvasRemotePort=9390,password=None,keyFile="",keyPassword=None):
        self.sshTunnel = None
        self.gmp = None
        if not self.connect(host,username,openvasUsername,openvasPassword,port,openvasRemotePort,password,keyFile,keyPassword):
            return None

    def connect(self,host,username,openvasUsername,openvasPassword,port,openvasRemotePort,password,keyFile,keyPassword):
        self.sshTunnel = SSHTunnelForwarder((host,port),ssh_username=username,ssh_password=password,ssh_pkey=str(Path(keyFile)),ssh_private_key_password=keyPassword,remote_bind_address=("127.0.0.1",openvasRemotePort))
        self.sshTunnel.start()
        self.sshTunnelPort = self.sshTunnel.local_bind_port

        openvasConnection = TLSConnection(hostname="127.0.0.1",port=self.sshTunnelPort)
        transform = EtreeTransform()
        self.gmpObj = Gmp(openvasConnection, transform=transform)
        self.gmp = self.gmpObj.__enter__()
        self.gmp.authenticate(openvasUsername,openvasPassword)
        return self.status()

    def status(self):
        if self.gmp.is_connected() and self.gmp.is_authenticated() and self.sshTunnel.is_alive:
            return True
        return False

    def disconnect(self):
        if self.gmpObj != None:
            self.gmpObj.__exit__()
            self.gmpObj = None
        if self.sshTunnel != None:
            self.sshTunnel.stop()
            self.sshTunnel = None

    def __del__(self):
        self.disconnect

    def getScanCount(self):
        totalScans = 0
        tasks = self.gmp.get_tasks(filter="name~Jimi")
        for task in tasks.xpath('task'):
            totalScans += 1
        return totalScans

    def createScan(self,scanName,configId,targetId,scannerId):
        result = self.gmp.create_task(scanName,configId,targetId,scannerId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(result, encoding='utf8', method='xml'))["create_task_response"]))

    def getScans(self):
        scans = self.gmp.get_tasks(filter="name~Jimi")
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(scans, encoding='utf8', method='xml'))["get_tasks_response"]))

    def getScan(self,scanId):
        scan = self.gmp.get_task(scanId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(scan, encoding='utf8', method='xml'))["get_tasks_response"]))

    def deleteScan(self,scanId):
        result = self.gmp.delete_task(scanId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(result, encoding='utf8', method='xml'))["delete_task_response"]))

    def startScan(self,scanId):
        result = self.gmp.start_task(scanId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(result, encoding='utf8', method='xml'))["start_task_response"]))

    def stopScan(self,scanId):
        result = self.gmp.stop_task(scanId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(result, encoding='utf8', method='xml'))["stop_task_response"]))

    def getScanners(self):
        scanners = self.gmp.get_scanners()
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(scanners, encoding='utf8', method='xml'))["get_scanners_response"]))

    def getConfigs(self):
        configs = self.gmp.get_configs()
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(configs, encoding='utf8', method='xml'))["get_configs_response"]))

    def getReportById(self,reportId):
        report = self.gmp.get_report(reportId,details=1,ignore_pagination=1)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(report, encoding='utf8', method='xml'))["get_reports_response"]))

    def deleteReport(self,reportId):
        result = self.gmp.delete_report(reportId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(result, encoding='utf8', method='xml'))["delete_report_response"]))

    def getTargetById(self,targetId):
        target = self.gmp.get_target(targetId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(target, encoding='utf8', method='xml'))["get_targets_response"]))

    def getTargetsByName(self,targetName):
        target = self.gmp.get_targets(filter="name~{0}".format(targetName))
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(target, encoding='utf8', method='xml'))["get_targets_response"]))

    def createTarget(self,targetName,target,portListId):
        result = self.gmp.create_target(targetName,hosts=target,port_list_id=portListId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(result, encoding='utf8', method='xml'))["create_target_response"]))

    def deleteTarget(self,targetId):
        result = self.gmp.delete_target(targetId)
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(result, encoding='utf8', method='xml'))["delete_target_response"]))

    def getPortLists(self):
        portList = self.gmp.get_port_lists()
        return json.loads(json.dumps(xmltodict.parse(ElementTree.tostring(portList, encoding='utf8', method='xml'))["get_port_lists_response"]))
