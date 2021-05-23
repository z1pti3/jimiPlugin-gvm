import jimi

class _gvm(jimi.plugin._plugin):
    version = 1.0

    def install(self):
        jimi.model.registerModel("gvmConnect","_gvmConnect","_action","plugins.gvm.models.action")
        jimi.model.registerModel("gvmDisconnect","_gvmDisconnect","_action","plugins.gvm.models.action")
        jimi.model.registerModel("gvmNewScan","_gvmNewScan","_action","plugins.gvm.models.action")
        jimi.model.registerModel("gvmGetScan","_gvmGetScan","_action","plugins.gvm.models.action")
        jimi.model.registerModel("gvmProcessScans","_gvmProcessScans","_action","plugins.gvm.models.action")
        jimi.model.registerModel("gvmScan","_gvmScan","_document","plugins.gvm.models.gvmScan")
        return True

    def uninstall(self):
        jimi.model.deregisterModel("gvmConnect","_gvmConnect","_action","plugins.gvm.models.action")
        jimi.model.deregisterModel("gvmDisconnect","_gvmDisconnect","_action","plugins.gvm.models.action")
        jimi.model.deregisterModel("gvmNewScan","_gvmNewScan","_action","plugins.gvm.models.action")
        jimi.model.deregisterModel("gvmGetScan","_gvmGetScan","_action","plugins.gvm.models.action")
        jimi.model.deregisterModel("gvmProcessScans","_gvmProcessScans","_action","plugins.gvm.models.action")
        jimi.model.deregisterModel("gvmScan","_gvmScan","_document","plugins.gvm.models.gvmScan")
        return True

    def upgrade(self,LatestPluginVersion):
        return True            
