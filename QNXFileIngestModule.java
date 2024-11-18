package org.KevinArgueta.autopsy.module;

import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.datamodel.AbstractFile;

public class QNXFileIngestModule implements FileIngestModule {

    public void startUp() {
        // Initialization code
    }

    @Override
    public ProcessResult process(AbstractFile file) {
        if (file.getNameExtension().equalsIgnoreCase("qnx6")) {
            // Add processing logic for QNX6 files
            System.out.println("Processing QNX6 file: " + file.getName());
        }
        return ProcessResult.OK;
    }

    @Override
    public void shutDown() {
        // Cleanup code
    }
}
