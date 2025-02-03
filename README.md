# QNX Parser plugin for Autopsy

A plugin for the Autopsy digital forensics platform that parses QNX6 image files and provides a tree directory structure. This tool is designed to help investigators analyze QNX-based Systems efficiently.

## Features

- Parses QNX6 disk images and extracts the filesystem into the export folder in the current case
- Displays the files and directores in the tree viewer
- Supports both GPT and (legacy) MBR partition types
- Works on VP4R's and VP4's
- Tested on Chryslers and Fords

## Installation

1. Go into the build folder and download the nbm file
2. Open Autopsy select Tools -> Plugins -> Downloaded -> Add Plugin -> select the nbm file -> install
3. restart Autopsy
4. Go back into Tools -> Installed -> check QNX Parser
5. Ready to Analyze
   
## Usage

1. Add a datasource (must be of a qnx6 image)
2. Choose unallocated disk image file
3. Add the disk image and do not break up image file
4. Once analysis is done you can check the tree viewer and view the filesystem manually or you can run ingest modules on it

## Other

- Be patient some QNX images analyze faster than others
- Make sure it is of type QNX image otherwise it will crash (eventually will fix this)
- If you believe Autopsy to have crashed look to see in the current case's folder and check the export folder to check if the parser is creating the folders and files
- Still working on features like viewing deleted blocks and redundancy in case of unexpected inputs
- Perhaps even a progress bar, but this pluging is the basis to efficiently analyze QNX images  

## Contributing 

- Any contributions are welcome.
- If you want to contribute make sure to have netbeans installed and integrated with Autopsy

## Acknowledgements

I Wouldn't have been able to do this project without the hard work of the following projects and its contributors:
- Most of the logic comes straight from Mathew Evan's (https://github.com/ReFirmLabs/qnx6-extractor/blob/master/qnx6_extractor/main.py)
- Inspiration for QNX parsing and understanding of the QNX system is thanks to the research of this repository (https://github.com/jdbonfils/QNX6FS-Parser-Ingest-Module?tab=readme-ov-file)
