package org.KevinArgueta.autopsy.module;

import org.openide.util.lookup.ServiceProvider;

import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

@ServiceProvider(service = IngestModuleFactory.class) 
public class QNXFileIngestModuleFactory implements IngestModuleFactory {
    
    private static final String VERSION_NUMBER = "1.0.0";

    @Override
    public String getModuleDisplayName() {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public String getModuleDescription() {
        throw new UnsupportedOperationException("Not supported yet."); 
    }

    @Override
    public String getModuleVersionNumber() {
        throw new UnsupportedOperationException("Not supported yet."); 
    }
    
}
