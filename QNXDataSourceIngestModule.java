package org.KevinArgueta.autopsy.module;

import org.sleuthkit.autopsy.ingest.FileIngestModule;
import org.sleuthkit.datamodel.AbstractFile;

// From datasourceingestmodule sample
import java.util.List;
import java.util.logging.Level;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress;
import org.sleuthkit.autopsy.ingest.IngestModule;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.ingest.DataSourceIngestModule;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestMessage;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.Image;

public class QNXDataSourceIngestModule implements DataSourceIngestModule {
    
    private IngestJobContext context = null;
    private static final Logger logger = Logger.getLogger(QNXDataSourceIngestModule.class.getName());
    private QNX6FS QNXFile;
    
    QNXDataSourceIngestModule() {
    }

    @Override
    public void startUp(IngestJobContext context) throws IngestModuleException {
        this.context = context;
    }
    
    @Override
    public ProcessResult process(Content dataSource, DataSourceIngestModuleProgress progressBar) {
        try {
            QNXFile = new QNX6FS(dataSource);
            // Iterate over Content objects in the data source
            for (Content content: dataSource.getChildren()) {
                if (content instanceof Image) {
                    QNXFile.getPartitions();
                }
            }
            System.out.println("Looking good");
            return ProcessResult.OK;
        }
        catch (Exception e) {
            e.printStackTrace();
            return ProcessResult.ERROR;
        }
        
    }

    public void parseQNXFileSystem(Image image) {
        
    }

}
