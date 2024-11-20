package org.KevinArgueta.autopsy.module;

import org.openide.util.lookup.ServiceProvider;

import org.sleuthkit.autopsy.ingest.IngestModuleFactory;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleGlobalSettingsPanel;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettingsPanel;

@ServiceProvider(service = IngestModuleFactory.class) 
public class QNXDataSourceIngestModuleFactory implements IngestModuleFactory {
    
    private static final String VERSION_NUMBER = "1.0.0";
    private static final String MODULE_NAME = "QNX parser";
    private static final String DESCRIPTION = "Able to analyze QNX file images";
    
    
    static String getModuleName() {
        return MODULE_NAME;
    }

    @Override
    public String getModuleDisplayName() {
        return getModuleName(); 
    }

    @Override
    public String getModuleDescription() {
        return DESCRIPTION; 
    }

    @Override
    public String getModuleVersionNumber() {
        return VERSION_NUMBER; 
    }
    
    @Override
    public boolean isDataSourceIngestModuleFactory() {
        return true;
    }
    
    @Override
    public DataSourceIngestModule createDataSourceIngestModule(IngestModuleIngestJobSettings settings) {
        if(!(settings instanceof QNXModuleIngestJobSettings)) {
            throw new IllegalArgumentException("Expected settings argument to be instanceof SampleModuleIngestJobSettings");
        }
        return (DataSourceIngestModule) new QNXDataSourceIngestModule((QNXModuleIngestJobSettings) settings);
    }
    
}
