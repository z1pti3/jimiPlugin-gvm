import time

import jimi

class _gvmScan(jimi.db._document):
    scannerId = str()
    conductId = str()
    flowId = str()
    target = str()
    targetId = str()
    configId = str()
    portListId = str()
    scanId = str()
    reportId = str()
    status = int()
    findings = list()
    requestTime = int()
    startTime = int()
    endTime = int()
    lastCheck = int()
    data = dict()

    _dbCollection = jimi.db.db["gvmScans"]

    def new(self,acl,conductId,flowId,target,configId,portListId,scannerId,data):
        self.acl = acl
        self.conductId = conductId
        self.flowId = flowId
        self.target = target
        self.configId = configId
        self.portListId = portListId
        self.scannerId = scannerId
        self.status = -1
        self.requestTime = int(time.time())
        self.startTime -1
        self.endTime = -1
        self.data = { 
            "flowData" : { 
                "event" : data["flowData"]["event"],
                "action" : data["flowData"]["action"], 
                "var" : data["flowData"]["var"] , 
                "plugin" : data["flowData"]["plugin"] 
            },
            "eventData" : { 
                "var" : data["eventData"]["var"] , 
                "plugin" : data["eventData"]["plugin"] 
            },
            "conductData" : { 
                "var" : data["conductData"]["var"] , 
                "plugin" : data["conductData"]["plugin"] 
            },
            "persistentData" : { 
                "var" : data["persistentData"]["var"] , 
                "plugin" : data["persistentData"]["plugin"] 
            }
        }
        return super(_gvmScan, self).new()
