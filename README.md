# QNX Parser plugin for Autopsy

A plugin for the Autopsy digital forensics platform that parses QNX6 image files and provides a tree directory structure. This tool is designed to help investigators analyze QNX-based Systems efficiently.

## Features

- Parses QNX6 disk image and extracts it into a folder called extracted (except longfilenames gosh darn)
- Displays the files and directores in the tree viewer (work in progress)

## Usage

1. Add a datasource
2. Choose unallocated disk image file
3. Add the disk image and do not break up image file

## Contributing 

Contributions are welcome, as of now it is not complete so any help is welcome.

## Acknowledgements

Wouldn't have been able to do this project with the hard work of the following project and its contributors:
- Was looking for the reference but couldn't find it ¯\_(ツ)_/¯
- Inspiration for QNX parsing and understanding of the QNX system is thanks to the research of this repository (https://github.com/jdbonfils/QNX6FS-Parser-Ingest-Module?tab=readme-ov-file)
