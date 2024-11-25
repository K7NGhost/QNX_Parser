/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package org.KevinArgueta.autopsy.module;

import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.TskCoreException;

import java.util.Map;
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
        int bytesRead = QNXImage.read(dataBlock, 0, 512);
        
        if (bytesRead < 512) {
            throw new TskCoreException("Unable to read complete MBR from the disk image.");
        }
    }
    
    
}
