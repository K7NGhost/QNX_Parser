package org.KevinArgueta.autopsy.module;

import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;

public class QNXModuleIngestJobSettings implements IngestModuleIngestJobSettings{
    private static final long serialVersionUID = 1L;
    private boolean skipKnownFiles = true;
    
    QNXModuleIngestJobSettings() {
        
    }
    
    QNXModuleIngestJobSettings(boolean skipKnownFiles) {
        this.skipKnownFiles = skipKnownFiles;
    }
    
    @Override
    public long getVersionNumber() {
        return serialVersionUID;
    }
    
    void setSkipKnownFiles(boolean enabled) {
        skipKnownFiles = enabled;
    }
    
    boolean skipKnownFiles() {
        return skipKnownFiles;
    }
    
    
}
