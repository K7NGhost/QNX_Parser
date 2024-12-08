/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.example.autopsy.testmodule;

import java.io.ByteArrayOutputStream;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.Volume;
import org.sleuthkit.datamodel.FileSystem;
import org.sleuthkit.datamodel.SleuthkitCase;

import java.util.Map;
import java.io.RandomAccessFile;
import java.util.HashMap;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.Math;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.lang.System;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import org.sleuthkit.datamodel.LocalDirectory;

import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.VolumeSystem;

public class QNX6FS {
    VolumeSystem volumeSystem;
    Volume volume;
    SleuthkitCase skCase;
    CaseDbTransaction transaction;
    
    
    public static final HashMap<String, Integer> PARTITION_MAGIC;
    private Map<Integer, Partition> nPartitionList = new HashMap<>();
    
    static {
        PARTITION_MAGIC = new HashMap<>();
        PARTITION_MAGIC.put("QNX4", 0x002f);
        PARTITION_MAGIC.put("QNX6", 0x68191122);
    }
    
    public static final HashMap<String, Integer> FILE_TYPE;
    static {
        FILE_TYPE = new HashMap<>();
        FILE_TYPE.put("DIRECTORY", 0X01);
        FILE_TYPE.put("DELETED", 0X02);
        FILE_TYPE.put("FILE", 0X03);
    }
    
    private int QNX6_SUPERBLOCK_SIZE = 0X200; //Superblock is fixed (512 bytes)
    private int QNX6_SUPERBLOCK_AREA = 0X1000; //Area reserved for superblock
    private int QNX6_BOOTBLOCK_SIZE = 0X2000; //Boot Block Size
    private int QNX6_DIR_ENTRY_SIZE = 0X20; //Dir block size (32 bytes)
    private int QNX6_INODE_SIZE = 0X80; //INode block size (128 bytes)
    private int QNX6_INODE_SIZE_BITS = 0X07; //INode entry size shift
    
    private int QNX6_NO_DIRECT_POINTERS = 16;
    private int QNX6_PTR_MAX_LEVELS = 5;
    private int QNX6_SHORT_NAME_MAX = 27;
    private int QNX6_LONG_NAME_MAX = 510;
    
    // for parseQNX
    private Content content;
    private long offset;
    private Map<String, Object> superBlock;
    
    // For parseBitmap
    private Map<Integer, Map<String, Object>> bitmaps = new HashMap<>();
    
    // For parseInode
    private Map<Integer, Map<String, Object>> inodeTree = new HashMap<>();
    private Map<Integer, String> longNames = new HashMap<>();
    private Map<Integer, Map<String, Object>> dirTree = new HashMap<>();  // DirTree equivalent

    
    public QNX6FS(Content content, SleuthkitCase skCase, CaseDbTransaction transaction) {
        this.skCase = skCase;
        this.transaction = transaction;
        this.content = content;
    }
    
    public void processQNX() throws TskCoreException, IOException {
        getPartitions(content, this.skCase, this.transaction);
        printPartitions();
        for (Map.Entry<Integer, Partition> entry: nPartitionList.entrySet()) {
            Partition partition = entry.getValue();
            if (partition.partitionType == 0x00) {
                
            }
            else {
                // Create the required partition map
                Map<String, Long> partitionMap = new HashMap<>();
                partitionMap.put("StartingOffset", partition.startingOffset);
                partitionMap.put("EndOffset", partition.endOffset);
                partitionMap.put("Size", (long) partition.partitionSize);
                parseQNX(content, partitionMap, entry.getKey());
            }
        }
           
        
    }
    
    public void getPartitions(Content image, SleuthkitCase skCase, CaseDbTransaction transaction) throws TskCoreException, IOException {
        if (!(image instanceof Image)) {
            throw new IllegalArgumentException("Provided Content is not a valid disk image");
        }
        
        Image QNXImage = (Image) image;
        
        // MBR is 512 bytes so we get the data to 512 from image
        byte[] dataBlock = new byte[512];
        int bytesRead;
        try (ReadContentInputStream inputStream = new ReadContentInputStream(QNXImage)) {
            bytesRead = inputStream.read(dataBlock, 0, 512);
        } catch (IOException ex) {
            throw new TskCoreException("Error reading MBR from disk image", ex);
        }
        
        if (bytesRead < 512) {
            throw new TskCoreException("Unable to read complete MBR from the disk image.");
        }
        
        // Extracts the first 446 bytes as boot code
        byte[] bootCode = new byte[446];
        // Extracts the next 64 bytes as the partition Table
        byte[] masterPartitionTable = new byte[64];
        // Extracts the last 2 bytes as the boot record signature
        byte[] bootRecordsSignature = new byte[2];
        
        // Getting the bytes into their respective variable
        System.arraycopy(dataBlock, 0, bootCode, 0, 446);
        System.arraycopy(dataBlock, 446, masterPartitionTable, 0, 64);
        System.arraycopy(dataBlock, 510, bootRecordsSignature, 0, 2);
        
        // Getting the bootrecordsignature and reverse little endian it
        ByteBuffer signatureBuffer = ByteBuffer.wrap(bootRecordsSignature).order(ByteOrder.LITTLE_ENDIAN);
        int bootRecordSignatureValue = signatureBuffer.getShort() & 0xFFFF; // Unsigned short
        
        // Check if it is MBR by analyzing the end
        if (bootRecordSignatureValue != 0xAA55) {
            throw new TskCoreException("[ERROR] Boot Record Signature Missing; Invalid Disk Image");
        }
        else {
            System.out.println("[-] Boot Record Signature detected");
        }
        
        // the MasterPartitionTable is 64 bytes in length each partition being 16 bytes
        parsePartitionMBR(masterPartitionTable, QNXImage);
        createVolumeSystemWithPartitions(skCase, QNXImage, nPartitionList, 512, transaction);
    }
    
    static class Partition {
        byte bootIndicator;
        byte[] startingCHS;
        byte partitionType;
        byte[] endingCHS;
        int startingSector;
        int partitionSize;
        int endingSector;
        long startingOffset;
        long endOffset;
        int sectorSize;
        boolean qnx6;
    }
    
    public Map<Integer, Partition> parsePartitionMBR(byte[] masterPartitionTable, Content image) throws IOException {
        Map<Integer, Partition> partitionList = new HashMap<>();
        
        // Look through the four partitions
        for (int i = 0; i < 4; i++) {
            // Each partition's entry offset is in bytes (imagine a stack where it start 0 and ends before the next block)
            int entryOffset = i * 16;
            Partition partition = new Partition();
            
            // Boot indicator - whether the partition is bootable (0x80 = bootable, 0x00 = not bootable)
            partition.bootIndicator = masterPartitionTable[entryOffset];
            partition.startingCHS = new byte[]{masterPartitionTable[entryOffset + 1], masterPartitionTable[entryOffset + 2], masterPartitionTable[entryOffset + 3]};
            // Identifies the file system or partition type
            partition.partitionType = masterPartitionTable[entryOffset + 4];
            partition.endingCHS = new byte[]{masterPartitionTable[entryOffset + 5], masterPartitionTable[entryOffset + 6], masterPartitionTable[entryOffset + 7]};
            
            // Important to calculate the partition's offsets
            // Starting Sector - The sector where the partition begins (4 bytes little endian)
            partition.startingSector = ByteBuffer.wrap(masterPartitionTable, entryOffset + 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            // Partition size - the toal number of sectors (4 bytes, little-endian)
            partition.partitionSize = ByteBuffer.wrap(masterPartitionTable, entryOffset + 12, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            
            // Ending Sector - Last sector of the partition
            partition.endingSector = partition.startingSector + partition.partitionSize - 1;
            // Starting Offset - Byte offset where the partition starts (sector x sector size)
            partition.startingOffset = partition.startingSector * 512L;
            // End offset - byte offset where the partition ends
            partition.endOffset = partition.endingSector * 512L;
            // Sector Size - Assumes a standard 512 bytes per sector
            partition.sectorSize = 512;
            partition.qnx6 = false;

            int partitionID = partition.partitionType & 0xFF;
            if (partitionID == 0x05 || partitionID == 0x0F) {
                System.out.println("[-] (EBR) Extended Boot Record Detected, Processing....");
                Map<Integer, Partition> extendedPartitions = parseExtendedPartitions(image, partition.startingSector, partition.sectorSize);
                partitionList.putAll(extendedPartitions);
                // Additional logic would go here for parsing extended partitions.
                
            } else if (partitionID == 0xB1 || partitionID == 0xB2 || partitionID == 0xB3 || partitionID == 0xB4) {
                System.out.printf("[+] Supported QNX6FS Partition Detected @ %02x%n", partition.startingOffset);
                partition.qnx6 = true;
            } else if (partitionID == 0x4D || partitionID == 0x4E || partitionID == 0x4F) {
                System.out.printf("[X] Unsupported QNX4FS Partition Detected @ %02x%n", partition.startingOffset);
            }

            partitionList.put(i+1, partition);
        }
        nPartitionList = partitionList;
        return partitionList;
    }
    
    private Map<Integer, Partition> parseExtendedPartitions(Content image, long extendedPartitionStart, int sectorSize) throws IOException {
    Map<Integer, Partition> partitionList = new HashMap<>();
    long currentEBROffset = extendedPartitionStart * sectorSize;
    int logicalPartitionNumber = 5; // Logical partitions usually start from 5

    while (true) {
        // Read the EBR at currentEBROffset
        ReadContentInputStream fileIO = new ReadContentInputStream(image);
        fileIO.skip(currentEBROffset);
        byte[] ebrData = new byte[sectorSize];
        fileIO.read(ebrData, 0, sectorSize);

        // Extract partition entries from the EBR
        byte[] partitionTable = Arrays.copyOfRange(ebrData, 446, 446 + 64);

        // Parse the first partition entry (logical partition)
        Partition logicalPartition = parsePartitionEntry(partitionTable, 0);

        // Check if the partition type is valid
        System.out.println(logicalPartition.partitionType);
        if (logicalPartition.partitionType == 0x00) {
            break; // No more logical partitions
        }
        
        int partitionID = logicalPartition.partitionType;
        if (partitionID == 0xB1 || partitionID == 0xB2 || partitionID == 0xB3 || partitionID == 0xB4) {
                System.out.printf("[+] Supported QNX6FS Partition Detected @ %02x%n", logicalPartition.startingOffset);
                logicalPartition.qnx6 = true;
            } else if (partitionID == 0x4D || partitionID == 0x4E || partitionID == 0x4F) {
                System.out.printf("[X] Unsupported QNX4FS Partition Detected @ %02x%n", logicalPartition.startingOffset);
            }

        // Calculate absolute starting sector and offset
        logicalPartition.startingSector = (int) ((currentEBROffset / sectorSize) + logicalPartition.startingSector);
        logicalPartition.startingOffset = logicalPartition.startingSector * (long) sectorSize;
        logicalPartition.endingSector = logicalPartition.startingSector + logicalPartition.partitionSize - 1;
        logicalPartition.endOffset = logicalPartition.endingSector * (long) sectorSize;
        logicalPartition.sectorSize = sectorSize;

        // Add the logical partition to the partition list
        System.out.println(logicalPartition.partitionType);
        partitionList.put(logicalPartitionNumber++, logicalPartition);

        // Parse the second partition entry (pointer to next EBR)
        Partition nextEBRPartition = parsePartitionEntry(partitionTable, 16);

        // Check if there is a next EBR
        if (nextEBRPartition.partitionType == 0x00) {
            break; // No more EBRs
        }

        // Update currentEBROffset for the next EBR
        currentEBROffset = extendedPartitionStart * sectorSize + nextEBRPartition.startingSector * (long) sectorSize;
    }

    return partitionList;
    }

    
    private Partition parsePartitionEntry(byte[] partitionTable, int entryOffset) {
    Partition partition = new Partition();

    partition.bootIndicator = partitionTable[entryOffset];
    partition.startingCHS = Arrays.copyOfRange(partitionTable, entryOffset + 1, entryOffset + 4);
    partition.partitionType = partitionTable[entryOffset + 4];
    partition.endingCHS = Arrays.copyOfRange(partitionTable, entryOffset + 5, entryOffset + 8);
    partition.startingSector = ByteBuffer.wrap(partitionTable, entryOffset + 8, 4)
                                         .order(ByteOrder.LITTLE_ENDIAN).getInt();
    partition.partitionSize = ByteBuffer.wrap(partitionTable, entryOffset + 12, 4)
                                        .order(ByteOrder.LITTLE_ENDIAN).getInt();

    return partition;
}
    
    public void parseQNX(Content image, Map<String, Long> partition, int partitionID) throws IOException, TskCoreException {
        try (ReadContentInputStream fileIO = new ReadContentInputStream(image)) {
            // Calculate initial offsets
            long startingOffset = partition.get("StartingOffset");
            long offset = QNX6_BOOTBLOCK_SIZE + startingOffset;
            this.offset = offset - QNX6_BOOTBLOCK_SIZE;
            
            // Skip past the boot block
            fileIO.skip(startingOffset + QNX6_BOOTBLOCK_SIZE);
            
            // Read the superblock (512 bytes)
            byte[] data = new byte[QNX6_SUPERBLOCK_SIZE];
            fileIO.read(data);
            Map<String, Object> superBlock = parseQNX6SuperBlock(data, startingOffset);
            this.superBlock = superBlock;
            
            // If the block size is not 512, re-read the superblock with correct size
            if ((int) superBlock.get("blocksize") != 512) {
                resetStream(fileIO, startingOffset + QNX6_BOOTBLOCK_SIZE);
                data = new byte[(int) superBlock.get("blocksize")];
                fileIO.read(data);
                superBlock = parseQNX6SuperBlock(data, startingOffset);
            }
            
            // Validate the superblock's magic value
            if ((int) superBlock.get("magic") == PARTITION_MAGIC.get("QNX6")) {
                System.out.printf(" |---+ First SuperBlock Detected ( Serial: %s ) @ %02x%n",
                        superBlock.get("serial"), offset);

                // Calculate backup superblock offset
                long backupSuperBlockOffset = startingOffset + QNX6_SUPERBLOCK_AREA + QNX6_BOOTBLOCK_SIZE
                        + ((int) superBlock.get("num_blocks") * (int) superBlock.get("blocksize"));
                resetStream(fileIO, backupSuperBlockOffset);
                data = new byte[(int) superBlock.get("blocksize")];
                fileIO.read(data);
                Map<String, Object> blkSuperBlock = parseQNX6SuperBlock(data, startingOffset);
                
                // validate backup superblock
                if ((int) blkSuperBlock.get("magic") == PARTITION_MAGIC.get("QNX6")) {
                    System.out.printf("     |---+ Second SuperBlock Detected ( Serial: %s ) @ %02x%n",
                            blkSuperBlock.get("serial"), backupSuperBlockOffset);

                    // Determine the active superblock
                    Map<String, Object> activeSuperBlock;
                    if ((long) blkSuperBlock.get("serial") < (long) superBlock.get("serial")) {
                        activeSuperBlock = superBlock;
                        System.out.println("         |---+ Using First SuperBlock as Active Block");
                    } else {
                        activeSuperBlock = blkSuperBlock;
                        System.out.println("         |---+ Using Second SuperBlock as Active Block");
                    }
                    
                    // Print superblock information and parse additional components
                    printSuperBlockInfo(activeSuperBlock);
                    parseBitmap(image, activeSuperBlock);
                    Map<Integer, String> longNames = new HashMap<>();
                    this.longNames = parseLongFileNames(image, activeSuperBlock);
                    longNames = this.longNames;
                    // Iterate through the map and print the key (formatted as hexadeciam) and value
                    if (longNames != null) {
                        for (Map.Entry<Integer, String> entry : longNames.entrySet()) {
                            System.out.printf("%02x: %s%n", entry.getKey(), entry.getValue());
                        }
                    }
                    
                    parseINODE(image, activeSuperBlock, partitionID);
                    
                }
            }
        }
            
        // TODO: create parseQNXSuperBlock DONE
        // TODO: create printSuperBlockInfo DONE
        // TODO: create parseBitmap DONE
        // TODO: create parseLongFileNames DONE
        // TODO: create parseINODE 
    }
    
    public void parseINODE(Content image, Map<String, Object> superBlock, int partitionID) throws IOException, TskCoreException {
        System.out.println("              |--+ Inode: Detected - Processing....");

        inodeTree = new HashMap<>();
        dirTree = new HashMap<>();

        // Check for valid inode structure
        Map<String, Object> inode = (Map<String, Object>) superBlock.get("Inode");
        if ((int) inode.get("level") > QNX6_PTR_MAX_LEVELS) {
            System.out.println("[x] Invalid Inode structure.");
            return;
        }

        // Process inode pointers
        int[] ptrArray = (int[]) inode.get("ptr");
        for (int n = 0; n < 16; n++) {
            int ptr = ptrArray[n];
            if (checkQNX6blkptr(ptr)) {
                long blocksize = ((Number) superBlock.get("blocksize")).longValue();
                long blksOffset = ((Number) superBlock.get("blks_offset")).longValue();
                long ptrOffset = (ptr * blocksize) + blksOffset;
                System.out.printf("                    |-- %d : %02x%n", n, ptrOffset);
                parseQNX6Inode(ptr, (int) inode.get("level"), blocksize, blksOffset, image);
            }
        }

        // Generate directory listing and extract files
        System.out.printf("[-] Generating directory Listing && Auto Extracting Files to (./Extracted/Partition%d)%n", partitionID);
        long blocksize = ((Number) superBlock.get("blocksize")).longValue();
        long blksOffset = ((Number) superBlock.get("blks_offset")).longValue();
        parseINodeDIRStruct(image, blocksize, blksOffset, 1);
        
        System.out.printf("dirTree size: %d%n", dirTree.size());
        for (int i : dirTree.keySet()) {
            System.out.println("Calling dump file");
            dumpFile(image, i, "./Extracted/", blocksize, blksOffset, partitionID);
        }
    }
    
    public void dumpFile(Content image, int dataINodeID, String outputDirectory, long blksize, long blkOffset, int partitionID) throws IOException, TskCoreException {
        // Get the inode data entry
        Map<String, Object> inodeDataEntry = inodeTree.get(dataINodeID);

        if (inodeDataEntry != null && !inodeEntryIsDir((int) inodeDataEntry.get("mode"))) {
            String filename = (String) dirTree.get(dataINodeID).get("Name");

            // Create directory path
            StringBuilder dirPath = new StringBuilder();
            int dirID = dataINodeID;
            while (true) {
                if (dirID <= 0x01) {
                    break;
                }
                if (dirID != dataINodeID) {
                    dirPath.insert(0, dirTree.get(dirID).get("Name") + File.separator);
                }
                dirID = (int) dirTree.get(dirID).get("ROOT_INODE");
            }
            
            // Create directory in Autopsy
        long parentId = volume.getId();
        long currentParentId = parentId;
        Content currentParent = skCase.getContentById(parentId);
        String[] directories = dirPath.toString().split(Pattern.quote(File.separator));

        for (String directoryName : directories) {
            if (!directoryName.isEmpty()) {
                LocalDirectory dir = skCase.addLocalDirectory(
                    currentParentId,
                    directoryName,
                    transaction
                );
                currentParentId = dir.getId();
                currentParent = dir;
            }
        }
        transaction.commit();

        // Ensure parent directory is valid
        if (currentParent == null) {
            System.err.printf("Parent directory is null for path: %s%n", dirPath);
            return;
        }

        // Add the file to Autopsy
        if (!inodeEntryIsDir((int) inodeDataEntry.get("mode"))) {
            // File metadata
            long size = ((Number) inodeDataEntry.get("size")).longValue();
            long ctime = ((Number) inodeDataEntry.getOrDefault("ctime", 0L)).longValue();
            long crtime = ((Number) inodeDataEntry.getOrDefault("crtime", 0L)).longValue();
            long atime = ((Number) inodeDataEntry.getOrDefault("atime", 0L)).longValue();
            long mtime = ((Number) inodeDataEntry.getOrDefault("mtime", 0L)).longValue();

            try {
                skCase.addLocalFile(
                    filename,
                    outputDirectory,         // Local path
                    size,
                    ctime * 1000,            // ctime in milliseconds
                    crtime * 1000,           // crtime in milliseconds
                    atime * 1000,            // atime in milliseconds
                    mtime * 1000,            // mtime in milliseconds
                    true,                    // Is file
                    TskData.EncodingType.NONE,
                    currentParent,           // Parent directory content
                    transaction
                );
            } catch (Exception e) {
                System.err.printf("Failed to add file '%s' under parent ID %d: %s%n", filename, currentParentId, e.getMessage());
            }
        }

            System.out.printf(" |--- [%s] \t %s%s%n", bytes2Human((long) inodeDataEntry.get("size")), dirPath, filename);

            // Create list of physical blocks
            List<Long> physicalPTRs = new ArrayList<>();
            int[] blockPtrs = (int[]) inodeDataEntry.get("block_ptr");
            for (int pointerIndex : blockPtrs) {
                if (pointerIndex != 0xFFFFFFFF) {
                    physicalPTRs.add((pointerIndex * blksize) + blkOffset);
                }
            }

            // Create output directory if it doesn't exist
            String fullDirPath = outputDirectory + "Partition" + partitionID + File.separator + dirPath;
            File dir = new File(fullDirPath);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            

            // Construct file path
            String filePath = fullDirPath + filename;
            File file = new File(filePath);
            
            // Print the full path of the output file
            System.out.printf("===============================Output file path: %s%n", filePath);
            System.out.println("Current working directory: " + System.getProperty("user.dir"));
            if (!file.exists()) {
                batchProcessPTRS(physicalPTRs, inodeDataEntry, (int) inodeDataEntry.get("filelevels"), blksize, blkOffset, filePath, image, null);
            }

            // Update file's access and modification times
            if (file.exists()) {
                long mtime = ((Number) inodeDataEntry.get("mtime")).longValue();
                file.setLastModified(mtime * 1000);
                // Setting access time is not directly supported in Java's standard API
                // FIX ME
            }
        }
    }
    
    public void batchProcessPTRS(List<Long> ptrs, Map<String, Object> inodeDataEntry, int level, long blksize, long blkOffset, String path, Content image, RandomAccessFile io) throws IOException {
        ReadContentInputStream fileIO = new ReadContentInputStream(image);
        if (io == null) {
            io = new RandomAccessFile(path, "rw");
        }

        // Buffer to store data
        ByteArrayOutputStream dataBuffer = new ByteArrayOutputStream();

        for (long ptr : ptrs) {
            if (level == 0) {
                if (checkQNX6blkptr(ptr)) {
                    if (ptr != 0xFFFFFFFFL && ptr != 0x0) {
                        fileIO.seek(ptr);
                        long remainingSize = (long) inodeDataEntry.get("size") - io.getFilePointer();

                        if (remainingSize >= 1024) {
                            byte[] data = new byte[(int) blksize];
                            fileIO.read(data);
                            dataBuffer.write(data);
                        } else {
                            byte[] data = new byte[(int) remainingSize];
                            fileIO.read(data);
                            dataBuffer.write(data);
                        }
                    }
                }
            } else {
                fileIO.seek(ptr);
                byte[] rawData = new byte[(int) blksize];
                fileIO.read(rawData);

                ByteBuffer buffer = ByteBuffer.wrap(rawData).order(ByteOrder.LITTLE_ENDIAN);
                List<Long> level2Ptrs = new ArrayList<>();

                for (int i = 0; i < blksize / 4; i++) {
                    long newPtr = buffer.getInt() & 0xFFFFFFFFL; // Unsigned integer
                    if (checkQNX6blkptr(newPtr)) {
                        if (newPtr != 0xFFFFFFFFL && newPtr != 0x0) {
                            level2Ptrs.add((newPtr * blksize) + blkOffset);
                        }
                    }
                }
                batchProcessPTRS(level2Ptrs, inodeDataEntry, level - 1, blksize, blkOffset, path, image, io);
            }
        }

        if (level == 0) {
            io.write(dataBuffer.toByteArray());
        }
    }
    
    public static String bytes2Human(long n) {
        if (n < 0) {
            throw new IllegalArgumentException("n < 0");
        }

        // Define symbols for byte units
        String[] symbols = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "IB"};

        // Traverse the symbols array to find the appropriate unit
        long prefix = 1L;
        for (int i = 0; i < symbols.length; i++) {
            if (n < prefix * 1024) {
                double value = (double) n / prefix;
                return String.format("%.1f %s", value, symbols[i]); // Default format
            }
            prefix *= 1024;
        }

        // If the value is extremely large, default to the largest unit
        double value = (double) n / prefix;
        return String.format("%.1f %s", value, symbols[symbols.length - 1]);
    }
    
    public void parseINodeDIRStruct(Content image, long blksize, long blksOffset, int inodeID) throws IOException {
        // Get the inode entry from the tree
        Map<String, Object> inodeEntry = inodeTree.get(inodeID);
        System.out.println("Processing inodeID: " + inodeID);
        System.out.println("inodeEntry: " + inodeEntry);

        // Check if the inode exists and is a directory
        if (inodeEntry != null && inodeEntryIsDir((int) inodeEntry.get("mode"))) {
            System.out.println("Inode is a directory");

            // Parse all 16 pointers in the inode entry
            List<Long> physicalPtrs = new ArrayList<>();
            int[] blockPtrs = (int[]) inodeEntry.get("block_ptr");
            System.out.println("block_ptr array: " + Arrays.toString(blockPtrs));
            
            for (int pointerIndex : blockPtrs) {
                // Skip invalid pointers (0xFFFFFFFF)
                if (pointerIndex != 0xFFFFFFFF) {
                    // Calculate physical location
                    physicalPtrs.add((pointerIndex * blksize) + blksOffset);
                }
            }
            System.out.println("Physical pointers: " + physicalPtrs);

            // Process valid pointers for directories and files
            if (!physicalPtrs.isEmpty()) {
                Map<String, Map<String, Object>> objects = parseInodeDirBatch(image, physicalPtrs, blksize, blksOffset);
                System.out.println("Objects from parseInodeDirBatch: " + objects);
                
                // Find parent inode ID (".")
                int rootID = 0;
                for (Map.Entry<String, Map<String, Object>> entry : objects.entrySet()) {
                    Map<String, Object> obj = entry.getValue();
                    if (".".equals(obj.get("Name"))) {
                        rootID = (int) obj.get("PTR");
                        break;
                    }
                }
                System.out.println("Root ID: " + rootID);

                // Process all objects
                for (Map.Entry<String, Map<String, Object>> entry : objects.entrySet()) {
                    Map<String, Object> obj = entry.getValue();
                    String name = (String) obj.get("Name");

                    if (!"..".equals(name) && !".".equals(name)) {
                        int ptr = (int) obj.get("PTR");
                        System.out.println("Adding to dirTree: " + ptr + " -> " + name);
                        
                        // Create a map manually instead of using Map.of
                        Map<String, Object> dirEntry = new HashMap<>();
                        dirEntry.put("Name", name);
                        dirEntry.put("ROOT_INODE", rootID);

                        dirTree.put(ptr, dirEntry);

                        // Recursively process directories
                        if (ptr > 1) {
                            System.out.println("Recursively processing inode: " + ptr);
                            parseINodeDIRStruct(image, blksize, blksOffset, ptr);
                        }
                    }
                }
            }
        }
        else {
            System.out.println("Inode is not a directory or does not exist.");
        }
    }
    
    public Map<String, Map<String, Object>> parseInodeDirBatch(Content image, List<Long> ptrs, long blksize, long blksOffset) throws IOException { 
        ReadContentInputStream fileIO = new ReadContentInputStream(image);
        Map<String, Map<String, Object>> dir = new HashMap<>();
        
        for (long ptr : ptrs) {
            // Seek to the pointer position
            fileIO.seek(ptr);

            // Read raw data of size `blksize`
            byte[] rawData = new byte[(int) blksize];
            fileIO.read(rawData);

            int numEntries = (int) (blksize / 32); // Each directory entry is 32 bytes
            
            for (int i = 0; i < numEntries; i++) {
                // Extract a single directory entry
                int start = i * 32;
                int end = (i + 1) * 32;
                byte[] raw = new byte[32];
                System.arraycopy(rawData, start, raw, 0, 32);

                // Parse entry if the first 4 bytes (PTR) are not zero
                ByteBuffer buffer = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
                int ptrValue = buffer.getInt(0);
                if (ptrValue != 0) {
                    String key = ptr + "-" + i;
                    Map<String, Object> dirEntry = new HashMap<>();
                    dirEntry.put("PTR", ptrValue);
                    dirEntry.put("Length", buffer.get(4) & 0xFF); // Unsigned byte

                    int length = (int) dirEntry.get("Length");
                    if (length <= QNX6_SHORT_NAME_MAX) {
                        // Extract short name (27 bytes)
                        byte[] nameBytes = new byte[27];
                        buffer.position(5);
                        buffer.get(nameBytes, 0, 27);

                        // Convert to string, removing null characters
                        String name = new String(nameBytes).replace("\0", "");
                        dirEntry.put("Name", name);
                    }
                    else {
                        // Extract long name using LongNames map
                        buffer.position(5);
                        int longNameKey = buffer.getInt();
                        dirEntry.put("Name", longNames.get(longNameKey + 1)); // Adjust key as needed
                    }
                    
                    dir.put(key, dirEntry);
                }
            }
        }
        return dir;
    }
    
    public void parseQNX6Inode(int ptr, int level, long blksize, long blksOffset, Content image) throws IOException { 
        ReadContentInputStream fileIO = new ReadContentInputStream(image);
        long ptr_ = (ptr * blksize) + blksOffset;
        
        if (checkQNX6blkptr(ptr_) && ptr != 0xFFFFFFFF) {
            // Seek to the pointer position
            fileIO.seek(ptr_);

            // Read raw data of size `blksize`
            byte[] rawData = new byte[(int) blksize];
            fileIO.read(rawData);
            
            if (level >= 1) {
                // Extract pointers from the raw data
                int numPointers = (int) (blksize / 4); // Number of 32-bit integers
                ByteBuffer buffer = ByteBuffer.wrap(rawData).order(ByteOrder.LITTLE_ENDIAN);
                int[] pointers = new int[numPointers];
                
                for (int i = 0; i < numPointers; i++) {
                    pointers[i] = buffer.getInt();
                }
                
                // Recursively process each valid pointer
                for (int i = 0; i < numPointers; i++) {
                    long newPtrOffset = (pointers[i] * blksize) + blksOffset;
                    if (checkQNX6blkptr(newPtrOffset)) {
                        parseQNX6Inode(pointers[i], level - 1, blksize, blksOffset, image);
                    }
                }
            }
            else {
                // Process inode entries if level == 0
                int inodeRange = (int) (blksize / 128); // Each inode entry is 128 bytes
                for (int i = 0; i < inodeRange; i++) {
                    try {
                        int start = i * 128;
                        int end = (i + 1) * 128;
                        byte[] entryData = new byte[128];
                        System.arraycopy(rawData, start, entryData, 0, 128);

                        Map<String, Object> inodeEntry = parseQNX6InodeEntry(entryData);
                        inodeTree.put(inodeTree.size() + 1, inodeEntry);
                    }
                    catch (Exception e) {
                        System.out.printf("Error processing inode %d: Tree Size: %d Ptr_: %02x Ptr: %02x%n",
                                i, inodeTree.size(), ptr_, ptr);
                        inodeTree.put(inodeTree.size() + 1, null);
                        break;
                    }
                }
            }
        }
    }
 
    
    public Map<String, Object> parseQNX6InodeEntry(byte[] ie) {
        Map<String, Object> inodeEntry = new HashMap<>();
        ByteBuffer buffer = ByteBuffer.wrap(ie).order(ByteOrder.LITTLE_ENDIAN);

        // Parse fields
        inodeEntry.put("size", buffer.getLong(0)); // 8 bytes
        inodeEntry.put("uid", buffer.getInt(8)); // 4 bytes
        inodeEntry.put("gid", buffer.getInt(12)); // 4 bytes
        inodeEntry.put("ftime", buffer.getInt(16)); // 4 bytes
        inodeEntry.put("mtime", buffer.getInt(20)); // 4 bytes
        inodeEntry.put("atime", buffer.getInt(24)); // 4 bytes
        inodeEntry.put("ctime", buffer.getInt(28)); // 4 bytes
        inodeEntry.put("mode", buffer.getShort(32) & 0xFFFF); // Unsigned short (2 bytes)
        inodeEntry.put("ext_mode", buffer.getShort(34) & 0xFFFF); // Unsigned short (2 bytes)

        // Parse block pointers (16 integers)
        int[] blockPtr = new int[16];
        for (int i = 0; i < 16; i++) {
            blockPtr[i] = buffer.getInt(36 + (i * 4));
        }
        inodeEntry.put("block_ptr", blockPtr);

        // Parse remaining fields
        inodeEntry.put("filelevels", buffer.get(100) & 0xFF); // Unsigned byte
        inodeEntry.put("status", buffer.get(101) & 0xFF); // Unsigned byte

        // Parse unknown2 (2 bytes)
        byte[] unknown2 = new byte[2];
        buffer.position(102);
        buffer.get(unknown2);
        inodeEntry.put("unknown2", unknown2);

        // Parse zero2 (6 integers)
        int[] zero2 = new int[6];
        for (int i = 0; i < 6; i++) {
            zero2[i] = buffer.getInt(104 + (i * 4));
        }
        inodeEntry.put("zero2", zero2);

        return inodeEntry;
    }
    
    // Helper method to reset the stream to a specific offset
    private void resetStream(ReadContentInputStream fileIO, long offset) throws IOException {
        ((ReadContentInputStream) fileIO).seek(offset);
    }
    
    public Map<Integer, String> parseLongFileNames(Content image, Map<String, Object> superBlock) throws IOException { 
        System.out.println("              |--+ Longfile: Detected - Processing....");
        
        // Extract Longfile details from the superblock
        Map<String, Object> longfile = (Map<String, Object>) superBlock.get("Longfile");
        int level = (int) longfile.get("level");
        long blocksize = ((Number) superBlock.get("blocksize")).longValue();
        long blksOffset = ((Number) superBlock.get("blks_offset")).longValue();
        int[] ptrArray = (int[]) longfile.get("ptr");
        
        if (level > QNX6_PTR_MAX_LEVELS) {
            System.out.println("                           *invalid levels, too many*");
            return null;
        }
        
        List<Map<String, String>> longnames = new ArrayList<>();
        
        // Process each pointer
        for (int n = 0; n < 16; n++) {
            int ptr = ptrArray[n];
            if (checkQNX6blkptr(ptr)) {
                long ptrB = (ptr * blocksize) + blksOffset;
                System.out.printf("                    |-- %d: %02x%n", n, ptrB);
                longnames.add(parseQNX6LongFilename(image, ptr, level, blocksize, blksOffset));
            }
        }
        
        // Create a dictionary of names and INode/PTRs
        Map<Integer, String> dict = new HashMap<>();
        int count = 1;
        
        for (Map<String, String> nameMap : longnames) {
            if (nameMap != null) {
                for (Map.Entry<String, String> entry : nameMap.entrySet()) {
                    if (entry.getValue() != null) {
                        dict.put(count, entry.getValue());
                        count++;
                    }
                }
            }
        }
        return dict;
    }
    
    public Map<String, String> parseQNX6LongFilename(Content image, long ptr, int level, long blksize, long blksOffset) throws IOException { 
        ReadContentInputStream fileIO = new ReadContentInputStream(image);
        
        // Seek to the appropriate location
        long position = (ptr * blksize) + blksOffset;
        fileIO.seek(position);
        
        // Read 512 bytes
        byte[] handle = new byte[512];
        fileIO.read(handle);

        Map<String, String> logFilenameNode = new HashMap<>();
        
        if (level == 0) {
            // Extract size
            ByteBuffer buffer = ByteBuffer.wrap(handle).order(ByteOrder.LITTLE_ENDIAN);
            int size = buffer.getShort(0) & 0xFFFF; // Unsigned short
            
            // Extract filename bytes
            if (size > 0) {
                byte[] fname = new byte[size];
                System.arraycopy(handle, 2, fname, 0, size);

                // Convert filename bytes to string
                StringBuilder filename = new StringBuilder();
                for (byte b : fname) {
                    filename.append((char) b);
                }
                
                logFilenameNode.put(String.valueOf(ptr), filename.toString().trim());
                return logFilenameNode;
            }
            else {
                return null;
            }
        }
        else {
            // Extract 128 pointers (32-bit integers)
            ByteBuffer buffer = ByteBuffer.wrap(handle).order(ByteOrder.LITTLE_ENDIAN);
            int[] pointers = new int[128];
            for (int i = 0; i < 128; i++) {
                pointers[i] = buffer.getInt(i * 4);
            }
            
            // Recursively process pointers 
            for (int i = 0; i < 128; i++) {
                if (checkQNX6blkptr(pointers[i])) {
                    Map<String, String> name = parseQNX6LongFilename(image, pointers[i], level - 1, blksize, blksOffset);
                    if (name != null) {
                        if (level >= 1) {
                            logFilenameNode.put(String.valueOf(pointers[i]), name.get(String.valueOf(pointers[i])));                          
                        }
                        else {
                            logFilenameNode.put(String.valueOf(pointers[i]), name.toString());
                        }
                    }
                }
            } 
        }
        return logFilenameNode;
    }

    
    public Map<String, Object> parseQNX6SuperBlock(byte[] sb, long offset) {
        Map<String, Object> SB = new HashMap<>();
        ByteBuffer buffer = ByteBuffer.wrap(sb).order(ByteOrder.LITTLE_ENDIAN);
        
        // Parse the fields in the superblock
        SB.put("magic", buffer.getInt(0)); // 4 bytes
        SB.put("checksum", ByteBuffer.wrap(sb, 4, 4).order(ByteOrder.BIG_ENDIAN).getInt());
        SB.put("checksum_calc", calculateCRC32(sb, 8, 504)); // Calculate CRC32 from bytes 8 to 511
        SB.put("serial", buffer.getLong(8)); // 8 bytes
        SB.put("ctime", buffer.getInt(16)); // 4 bytes
        SB.put("atime", buffer.getInt(20)); // 4 bytes
        SB.put("flags", buffer.getInt(24)); // 4 bytes
        SB.put("version1", buffer.getShort(28)); // 2 bytes
        SB.put("version2", buffer.getShort(30)); // 2 bytes
        
         // Volume ID (16 bytes)
        byte[] volumeId = new byte[16];
        System.arraycopy(sb, 32, volumeId, 0, 16);
        SB.put("volumeid", volumeId);
        
        // Remaining fields
        SB.put("blocksize", buffer.getInt(48)); // 4 bytes
        SB.put("num_inodes", buffer.getInt(52)); // 4 bytes
        SB.put("free_inodes", buffer.getInt(56)); // 4 bytes
        SB.put("num_blocks", buffer.getInt(60)); // 4 bytes
        SB.put("free_blocks", buffer.getInt(64)); // 4 bytes
        SB.put("allocgroup", buffer.getInt(68)); // 4 bytes
        
        // Root node structures
        // TODO: Add parseQNX6RootNode
        SB.put("Inode", parseQNX6RootNode(subArray(sb, 72, 80))); // 80 bytes
        SB.put("Bitmap", parseQNX6RootNode(subArray(sb, 152, 80))); // 80 bytes
        SB.put("Longfile", parseQNX6RootNode(subArray(sb, 232, 80))); // 80 bytes
        SB.put("Unknown", parseQNX6RootNode(subArray(sb, 312, 80))); // 80 bytes
        
        // Calculate the block offset
        SB.put("blks_offset", offset + QNX6_SUPERBLOCK_AREA + QNX6_BOOTBLOCK_SIZE);
        
        return SB;
    }
    
    private long calculateCRC32(byte[] data, int start, int length) {
        CRC32 crc = new CRC32();
        crc.update(data, start, length);
        return crc.getValue() & 0xFFFFFFFFL;
    }
    
    private byte[] subArray(byte[] array, int start, int length) {
        byte[] subArray = new byte[length];
        System.arraycopy(array, start, subArray, 0, length);
        return subArray;
    }
    
    public Map<String, Object> parseQNX6RootNode(byte[] rn) {
        Map<String, Object> RN = new HashMap<>();
        ByteBuffer buffer = ByteBuffer.wrap(rn).order(ByteOrder.LITTLE_ENDIAN);
        
        // Extract fields from the byte array
        RN.put("size", buffer.getLong(0)); // 8 byte sfor size (64 bit)
        
        // Extract 16 integers (32-bit each) starting at byte offset 8
        int[] ptr = new int[16];
        for (int i = 0; i < 16; i++) {
            ptr[i] = buffer.getInt(8 + i * 4); // Each integer is 4 bytes
        }
        RN.put("ptr", ptr);
        
        // Extract level (1 byte) at offset 72
        RN.put("level", Byte.toUnsignedInt(buffer.get(72))); // Convert to unsigned
        
        // Extract mode (1 byte) at offset 73
        RN.put("mode", Byte.toUnsignedInt(buffer.get(73))); // Convert to unsigned
        
        // Extract 6 reserved bytes starting at offset 74
        byte[] reserved = new byte[6];
        System.arraycopy(rn, 74, reserved, 0, 6);
        RN.put("reserved", reserved);
        
        return RN;
    }
    
    public void parseBitmap(Content image, Map<String, Object> superBlock) throws IOException {
        System.out.println("              |--+ Bitmap: Detected - Processing.... (using fast mode, this will still take a while.)");
        
        // Extract bitmap details
        Map<String, Object> bitmap = (Map<String, Object>) superBlock.get("Bitmap");
        long blocksize = ((Number) superBlock.get("blocksize")).longValue();
        long blksOffset = ((Number) superBlock.get("blks_offset")).longValue();
        
        // Check bitmap level validity
        int level = (int) bitmap.get("level");
        if (level > QNX6_PTR_MAX_LEVELS) {
            System.out.println("                 *invalid levels, too many*");
            return;
        }
        
        // Process pointers
        int[] ptrArray = (int[]) bitmap.get("ptr");
        for (int n = 0; n < 16; n++) {
            int ptr = ptrArray[n];
            if (checkQNX6blkptr(ptr)) {
                long ptrOffset = (ptr * blocksize) + blksOffset;
                parseQNX6Bitmap(image, ptr, level, blocksize, blksOffset);
            }
        }

        // Analyze bitmap data
        int dcount = 0;
        int count = 0;
        
        if (!bitmaps.isEmpty()) {
            for (int i = 1; i < bitmaps.size(); i++) {
                Map<String, Object> bitmapData = bitmaps.get(i);
                byte[] data = (byte[]) bitmapData.get("DATA");
                
                for (byte b : data) {
                    for (int ii = 0; ii < 8; ii++) {
                        int bit = (b >> ii) & 0x01;
                        
                        if (bit == 0) {
                            if (!isBlockEmpty(count, blocksize, blksOffset, image)) {
                                dcount++;
                                long physicalPtr = (count * blocksize) + blksOffset;
                                String snippet = getSnippet(count, blocksize, blksOffset, image);
                                // Uncomment the following line to print deleted data details
                                //System.out.printf("                 |---Deleted Data @: %02x (%s)%n", physicalPtr, snippet); 
                            }
                        }
                        count++;
                    }
                }
            }
        }
        
        // Print summary of deleted blocks
        System.out.printf("                 |---Deleted Blocks: %d found%n", dcount);
        
        
        // TODO: Create checkQNX6blkptr Done
        // TODO: create parseQNX6Bitmap Done
        // TODO: create isBlockEmpty Done
        // TODO: create getSnippet Done
        
    }
    
    public void parseQNX6Bitmap(Content image, int ptr, int level, long blksize, long blksOffset) throws IOException { 
        ReadContentInputStream fileIO = new ReadContentInputStream(image);
        long ptr_ = (ptr * blksize) + blksOffset;
        
        if (checkQNX6blkptr(ptr_) && ptr != 0xFFFFFFFF) { 
            // Seek to the pointer position
            fileIO.seek(ptr_);

            // Read raw data of size `blksize`
            byte[] rawData = new byte[(int) blksize];
            fileIO.read(rawData);
            
            if (level >= 1) {
                // Extract pointers from the raw data
                int numPointers = (int) (blksize / 4); // Number of 32-bit integers in `rawData`
                ByteBuffer buffer = ByteBuffer.wrap(rawData).order(ByteOrder.LITTLE_ENDIAN);
                int[] pointers = new int[numPointers];
                
                for (int i = 0; i < numPointers; i++) {
                    pointers[i] = buffer.getInt();
                }
                
                // Recursively process each valid pointer
                for (int i = 0; i < numPointers; i++) {
                    long newPtrOffset = (pointers[i] * blksize) + blksOffset;
                    if (checkQNX6blkptr(newPtrOffset) && pointers[i] != 0xFFFFFFFF && pointers[i] != 0x0) {
                        parseQNX6Bitmap(image, pointers[i], level - 1, blksize, blksOffset);
                    }
                }
            }
            else {
                // Add raw data to the bitmaps map if level is 0
                Map<String, Object> bitmapData = new HashMap<>();
                bitmapData.put("PTR", ptr_);
                bitmapData.put("DATA", rawData);
                bitmaps.put(bitmaps.size() + 1, bitmapData);
            }
        }
    }
    
    public boolean isBlockEmpty(long blockNumber, long blksize, long blksOffset, Content image) throws IOException { 
        ReadContentInputStream fileIO = new ReadContentInputStream(image);
        // Calculate the physical pointer
        long physicalPtr = (blockNumber * blksize) + blksOffset;
        
        // Seek to the pointer position
        fileIO.seek(physicalPtr);
        
        // Read raw data of size `blksize`
        byte[] data = new byte[(int) blksize];
        fileIO.read(data);
        
        // Filter out null bytes and other non-zero values
        StringBuilder filteredData = new StringBuilder();
        for (byte b : data) {
            if ((b & 0xFF) > 0) { // Convert byte to unsigned and check if > 0
                filteredData.append((char) b);
            }
        }
        
        // Return true if the filtered data is empty
        return filteredData.length() < 1;
    }
    
    public String getSnippet(long blockNumber, long blksize, long blksOffset, Content image) throws IOException { 
        ReadContentInputStream fileIO = new ReadContentInputStream(image);
        // Calculate the physical pointer
        long physicalPtr = (blockNumber * blksize) + blksOffset;
        
        // Seek to the pointer position
        fileIO.seek(physicalPtr);
        
        // Read the first 40 bytes of data
        byte[] rawData = new byte[40];
        fileIO.read(rawData);
        
        // Convert raw data to a string
        String data = new String(rawData, "UTF-8");
        
        // Remove non-ASCII characters
        data = Pattern.compile("[^\\x00-\\x7F]").matcher(data).replaceAll("");
        
        // Filter characters with ASCII values between 20 and 127
        StringBuilder filteredData = new StringBuilder();
        for (char ch : data.toCharArray()) {
            if (ch > 20 && ch < 128) {
                filteredData.append(ch);
            }
        }
        
        // Trim leading and trailing whitespace
        return filteredData.toString().trim();
    }


    
    // Method to check if a block pointer is valid
    public boolean checkQNX6blkptr(long ptr) {
        long mask = (1L << Long.toBinaryString(ptr).length()) - 1;
        return (ptr ^ mask) != 0;
    }
    
    // Method to check if an inode entry is a directory
    public boolean inodeEntryIsDir(int mode) {
         return (mode & 040000) == 040000; // Correct syntax for octal literals in Java
    }
    
    // Method to check if an inode entry is a regular file
    public boolean inodeEntryIsReg(int mode) {
        return (mode & 0b10000000000000000) == 0b10000000000000000; // 0100000 in octal
    }
    
    // Method to check if an inode entry is a symbolic link
    public boolean inodeEntryIsLnk(int mode) {
        return (mode & 0b10100000000000000) == 0b10100000000000000; // 0120000 in octal
    }
   
    public void printSuperBlockInfo(Map<String, Object> SB) {
        // Print the bolume ID as a hexadeciaml string in uppercase
        byte[] volumeId = (byte[]) SB.get("volumeid");
        StringBuilder volumeIdHex = new StringBuilder();
        for (byte b : volumeId) {
            volumeIdHex.append(String.format("%02X", b));
        }
        
        System.out.println("              |--- volumeID:\t" + volumeIdHex);
        
        // Print the checksum in hexadecimal format
        int checksumInt = (int) SB.get("checksum"); // Retrieve as an Integer
        long checksum = Integer.toUnsignedLong(checksumInt); // Convert to unsigned long
        System.out.printf("              |--- checksums:\t0x%08X%n", checksum);
        
        // Print the number of inodes
        int numInodes = (int) SB.get("num_inodes");
        System.out.println("              |--- num_inodes:\t" + numInodes);
        
        // Print the number of blocks
        int numBlocks = (int) SB.get("num_blocks");
        System.out.println("              |--- num_blocks:\t" + numBlocks);
        
        // Print the block size
        int blockSize = (int) SB.get("blocksize");
        System.out.println("              |--- blocksize:\t" + blockSize);
        
        // Print the block offset
        long blockOffset = (long) SB.get("blks_offset");
        System.out.println("              |--- blkoffset:\t" + blockOffset);
    }
    
    public void printPartitions() {
        for (Map.Entry<Integer, Partition> entry : nPartitionList.entrySet()) {
            Partition partition = entry.getValue();
            System.out.printf("Partition %d:%n", entry.getKey());
            System.out.printf("  Boot Indicator: 0x%02X%n", partition.bootIndicator);
            System.out.printf("  Partition Type: 0x%02X%n", partition.partitionType);
            System.out.printf("  Starting Sector: %d%n", partition.startingSector);
            System.out.printf("  Partition Size: %d sectors%n", partition.partitionSize);
            System.out.printf("  Starting Offset: %d bytes%n", partition.startingOffset);
            System.out.printf("  Ending Offset: %d bytes%n", partition.endOffset);
            System.out.printf("  QNX6 Filesystem: %b%n", partition.qnx6);
        }
    }
    
    // ==========================================================================================================================================================================
    // Adding to the treeviewer in autopsy
    
    public void createVolumeSystemWithPartitions (SleuthkitCase skCase, Content dataSource, Map<Integer, Partition> partitions, long sectorSize, CaseDbTransaction transaction) throws TskCoreException {
        // Parent Id: the data source's object ID 
        long parentObjId = dataSource.getId();
        try {
            this.volumeSystem = skCase.addVolumeSystem(parentObjId, TskData.TSK_VS_TYPE_ENUM.TSK_VS_TYPE_UNSUPP, 0, sectorSize, transaction);
            System.out.println("VolumeSystem created with ID: " + volumeSystem.getId());
            // Step 2: Add each partition as a Volume
            long addr = 0;
            for (Map.Entry<Integer, Partition> entry : partitions.entrySet()) {          
                Partition partition = entry.getValue();
                if (partition.partitionType == 0x00) {
                }
                else {
                    this.volume = skCase.addVolume(volumeSystem.getId(),
                            
                        addr++, 
                        partition.startingSector, 
                        partition.partitionSize, 
                        "Partition Type: " + String.format("0x%02X", partition.partitionType & 0xFF), 
                        TskData.TSK_VS_PART_FLAG_ENUM.TSK_VS_PART_FLAG_ALLOC.getVsFlag(),
                        transaction);
                System.out.printf("Added Volume: Start Sector=%d, Size=%d%n",
                          partition.startingSector, partition.partitionSize);
                }
                
            }
            //transaction.commit();
        }
        catch (TskCoreException e) {
            if (transaction != null) {
                transaction.rollback();
            }
            System.err.println("Error during transaction: " + e.getMessage());
            throw e;
        }
        finally {
            //skCase.close();
        }
        
        
    }
    
    
}
