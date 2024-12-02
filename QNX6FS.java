/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.KevinArgueta.autopsy.module;

import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.ReadContentInputStream;

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
import java.util.Base64;

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
    
    public void getPartitions() throws TskCoreException {
        if (!(content instanceof Image)) {
            throw new IllegalArgumentException("Provided Content is not a valid disk image");
        }
        
        Image QNXImage = (Image) content;
        
        // Read the first 512 bytes (MBR)
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
        
        // split DataBlock into parts
        byte[] bootCode = new byte[446];
        byte[] masterPartitionTable = new byte[64];
        byte[] bootRecordsSignature = new byte[2];
        
        System.arraycopy(dataBlock, 0, bootCode, 0, 446);
        System.arraycopy(dataBlock, 446, masterPartitionTable, 0, 64);
        System.arraycopy(dataBlock, 510, bootRecordsSignature, 0, 2);
        
        // Verify the Boot Record Signature
        ByteBuffer signatureBuffer = ByteBuffer.wrap(bootRecordsSignature).order(ByteOrder.LITTLE_ENDIAN);
        int bootRecordSignatureValue = signatureBuffer.getShort() & 0xFFFF; // Unsigned short
        
        if (bootRecordSignatureValue != 0xAA55) {
            throw new TskCoreException("[ERROR] Boot Record Signature Missing; Invalid Disk Image");
        }
        else {
            System.out.println("[-] Boot Record Signature detected");
        }
        
        parsePartitionMBR(QNXImage, masterPartitionTable, 0);
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
        Content content;
    }
    
    public Map<Integer, Partition> parsePartitionMBR(Content content, byte[] partitionTable, long baseOffset) throws TskCoreException {
        Map<Integer, Partition> partitionList = new HashMap<>();

        for (int i = 0; i < 4; i++) {
            int entryOffset = i * 16;
            Partition partition = new Partition();

            partition.bootIndicator = partitionTable[entryOffset];
            partition.startingCHS = new byte[]{partitionTable[entryOffset + 1], partitionTable[entryOffset + 2], partitionTable[entryOffset + 3]};
            partition.partitionType = partitionTable[entryOffset + 4];
            partition.endingCHS = new byte[]{partitionTable[entryOffset + 5], partitionTable[entryOffset + 6], partitionTable[entryOffset + 7]};

            partition.startingSector = ByteBuffer.wrap(partitionTable, entryOffset + 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            partition.partitionSize = ByteBuffer.wrap(partitionTable, entryOffset + 12, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
            
            // Skip if the partition is empty
            if (partition.partitionType == 0 || partition.partitionSize == 0) {
                continue;
            }
            
            partition.endingSector = partition.startingSector + partition.partitionSize - 1;
            partition.startingOffset = baseOffset + (partition.startingSector * 512L);
            partition.endOffset = partition.startingOffset + (partition.partitionSize * 512L);
            partition.sectorSize = 512;
            partition.qnx6 = false;

            int partitionID = partition.partitionType & 0xFF;
            if (partitionID == 0x05 || partitionID == 0x0F) {
                System.out.println("[-] (EBR) Extended Boot Record Detected, Processing....");
                parseEBR(content, partitionList, partition.startingOffset);
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
    
    private void parseEBR(Content content, Map<Integer, Partition> partitionList, long extendedPartitionOffset) throws TskCoreException {
        System.out.println("Currently in the method that process the extened boot record");
        long currentOffset = extendedPartitionOffset;
        System.out.println("the current offset is " + currentOffset);

        while (currentOffset != 0) {
            try (ReadContentInputStream inputStream = new ReadContentInputStream(content)) {
                byte[] ebrBlock = new byte[512];
                inputStream.seek(currentOffset);
                int bytesRead = inputStream.read(ebrBlock, 0, 512);
                System.out.println("The bytes read is " + bytesRead);
                if (bytesRead == 512) {
                    byte[] logicalPartitionTable = new byte[64];
                    System.arraycopy(ebrBlock, 446, logicalPartitionTable, 0, 64);

                    Partition logicalPartition = new Partition();
                    logicalPartition.bootIndicator = logicalPartitionTable[0];
                    logicalPartition.partitionType = logicalPartitionTable[4];
                    logicalPartition.startingSector = ByteBuffer.wrap(logicalPartitionTable, 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                    logicalPartition.partitionSize = ByteBuffer.wrap(logicalPartitionTable, 12, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();

                    if (logicalPartition.partitionType == 0 || logicalPartition.partitionSize == 0) {
                        break;
                    }

                    logicalPartition.startingOffset = extendedPartitionOffset + (logicalPartition.startingSector * 512L);
                    logicalPartition.endOffset = logicalPartition.startingOffset + (logicalPartition.partitionSize * 512L);
                    logicalPartition.sectorSize = 512;
                    logicalPartition.qnx6 = (logicalPartition.partitionType == 0xB1 || logicalPartition.partitionType == 0xB2 ||
                            logicalPartition.partitionType == 0xB3 || logicalPartition.partitionType == 0xB4);

                    partitionList.put(partitionList.size(), logicalPartition);

                    // Move to next EBR if available
                    int nextEBRStart = ByteBuffer.wrap(ebrBlock, 462, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                    if (nextEBRStart == 0) {
                        break;
                    }

                    currentOffset = extendedPartitionOffset + (nextEBRStart * 512L);
                }
                else {
                    System.out.println("exiting loop");
                }
            } catch (IOException e) {
                throw new TskCoreException("Error reading Extended Boot Record from disk image", e);
            }
        }
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
    
    
}
