/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.example.autopsy.testmodule;

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
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.sleuthkit.datamodel.SleuthkitCase.CaseDbTransaction;
import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.VolumeSystem;

public class QNX6FS {
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
    
    private Content content;
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
    
    public QNX6FS(Content content) {
        this.content = content;
    }
    
    public void getPartitions(SleuthkitCase skCase, CaseDbTransaction transaction) throws TskCoreException, IOException {
        if (!(content instanceof Image)) {
            throw new IllegalArgumentException("Provided Content is not a valid disk image");
        }
        
        Image QNXImage = (Image) content;
        
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
            VolumeSystem volumeSystem = skCase.addVolumeSystem(parentObjId, TskData.TSK_VS_TYPE_ENUM.TSK_VS_TYPE_UNSUPP, 0, sectorSize, transaction);
            System.out.println("VolumeSystem created with ID: " + volumeSystem.getId());
            // Step 2: Add each partition as a Volume
            long addr = 0;
            for (Map.Entry<Integer, Partition> entry : partitions.entrySet()) {          
                Partition partition = entry.getValue();
                if (partition.partitionType == 0x00) {
                    
                }
                else {
                    skCase.addVolume(volumeSystem.getId(),
                            
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
