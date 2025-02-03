# QNX Parser plugin for Autopsy

A plugin for the Autopsy digital forensics platform that parses QNX6 image files and provides a tree directory structure. This tool is designed to help investigators analyze QNX-based Systems efficiently.

## Features

- Parses QNX6 disk images and extracts the filesystem into the export folder in the current case
- Displays the files and directores in the tree viewer

## Usage

1. Add a datasource
2. Choose unallocated disk image file
3. Add the disk image and do not break up image file

## Contributing 

Contributions are welcome.

## Acknowledgements

I Wouldn't have been able to do this project without the hard work of the following projects and its contributors:
- Most of the logic comes straight from Mathew Evan's (https://github.com/ReFirmLabs/qnx6-extractor/blob/master/qnx6_extractor/main.py)
- Inspiration for QNX parsing and understanding of the QNX system is thanks to the research of this repository (https://github.com/jdbonfils/QNX6FS-Parser-Ingest-Module?tab=readme-ov-file)
