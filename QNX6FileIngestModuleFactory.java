package org.KevinArgueta.autopsy.module;

import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.autopsy.ingest.IngestModuleFactoryAdapter;
import org.sleuthkit.autopsy.ingest.IngestModuleIngestJobSettings;


public class QNX6FileIngestModuleFactory extends IngestModuleFactoryAdapter {

    @Override
    public String getModuleDisplayName() {
        return "QNX6 File Processor";
    }

    @Override
    public String getModuleDescription() {
        return "Processes QNX6 image files.";
    }

    @Override
    public String getModuleVersionNumber() {
        return "1.0.0";
    }

    @Override
    public FileIngestModule createFileIngestModule(IngestModuleIngestJobSettings settings) {
        return new QNXFileIngestModule();
    }
}
