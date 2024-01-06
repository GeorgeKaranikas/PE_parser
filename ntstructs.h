#pragma once




typedef struct _IMAGE_DOS_HEADER {
    
      WORD e_magic;  // Magic Number - Usually = MZ (hex 5A4D defined as IMAGE_DOS_SIGNATURE )
      WORD e_cblp;   // Bytes on last page of file
      WORD e_cp;     // Pages in file
      WORD e_crlc;    //Relocations
      WORD e_cparhdr;   // size of paragraph header
      WORD e_minalloc;   // Min Paragraphs needed extra
      WORD e_maxalloc;   // Max Paragraphs needed extra
      WORD e_ss;    // intitial ss value
      WORD e_sp;    // inttial sp value
      WORD e_csum;   // checksum
      WORD e_ip;   // initial ip value
      WORD e_cs;    //intial cs value
      WORD e_lfarlc;   //file address relocation value
      WORD e_ovno;      // overlay address
      WORD e_res[4];     // reserved words  ( 8 bytes total)
      WORD e_oemid;      // OEM id
      WORD e_oeminfo;     // OEM information
      WORD e_res2[10];     // reserved bytes ( 20 bytes total)
      LONG e_lfanew;       // This is the address the PE header starts
    } IMAGE_DOS_HEADER,*PIMAGE_DOS_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
      DWORD VirtualAddress;
      DWORD Size;
    } IMAGE_DATA_DIRECTORY,*PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_NT_HEADERS {
      DWORD Signature;
      IMAGE_FILE_HEADER FileHeader;
      IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADERS32,*PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
      DWORD Signature;
      IMAGE_FILE_HEADER FileHeader;
      IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    } IMAGE_NT_HEADERS64,*PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_FILE_HEADER {
      WORD Machine;
      WORD NumberOfSections;
      DWORD TimeDateStamp;
      DWORD PointerToSymbolTable;
      DWORD NumberOfSymbols;
      WORD SizeOfOptionalHeader;
      WORD Characteristics;
    } IMAGE_FILE_HEADER,*PIMAGE_FILE_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {

      WORD Magic;
      BYTE MajorLinkerVersion;
      BYTE MinorLinkerVersion;
      DWORD SizeOfCode;
      DWORD SizeOfInitializedData;
      DWORD SizeOfUninitializedData;
      DWORD AddressOfEntryPoint;
      DWORD BaseOfCode;
      DWORD BaseOfData;
      DWORD ImageBase;
      DWORD SectionAlignment;
      DWORD FileAlignment;
      WORD MajorOperatingSystemVersion;
      WORD MinorOperatingSystemVersion;
      WORD MajorImageVersion;
      WORD MinorImageVersion;
      WORD MajorSubsystemVersion;
      WORD MinorSubsystemVersion;
      DWORD Win32VersionValue;
      DWORD SizeOfImage;
      DWORD SizeOfHeaders;
      DWORD CheckSum;
      WORD Subsystem;
      WORD DllCharacteristics;
      DWORD SizeOfStackReserve;
      DWORD SizeOfStackCommit;
      DWORD SizeOfHeapReserve;
      DWORD SizeOfHeapCommit;
      DWORD LoaderFlags;
      DWORD NumberOfRvaAndSizes;
      IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32,*PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
      WORD Magic;
      BYTE MajorLinkerVersion;
      BYTE MinorLinkerVersion;
      DWORD SizeOfCode;
      DWORD SizeOfInitializedData;
      DWORD SizeOfUninitializedData;
      DWORD AddressOfEntryPoint;
      DWORD BaseOfCode;
      ULONGLONG ImageBase;
      DWORD SectionAlignment;
      DWORD FileAlignment;
      WORD MajorOperatingSystemVersion;
      WORD MinorOperatingSystemVersion;
      WORD MajorImageVersion;
      WORD MinorImageVersion;
      WORD MajorSubsystemVersion;
      WORD MinorSubsystemVersion;
      DWORD Win32VersionValue;
      DWORD SizeOfImage;
      DWORD SizeOfHeaders;
      DWORD CheckSum;
      WORD Subsystem;
      WORD DllCharacteristics;
      ULONGLONG SizeOfStackReserve;
      ULONGLONG SizeOfStackCommit;
      ULONGLONG SizeOfHeapReserve;
      ULONGLONG SizeOfHeapCommit;
      DWORD LoaderFlags;
      DWORD NumberOfRvaAndSizes;
      IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER64,*PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
	DWORD Characteristics;
	DWORD OriginalFirstThunk;
      } DUMMYUNIONNAME;
      DWORD TimeDateStamp;
      DWORD ForwarderChain;
      DWORD Name;
      DWORD FirstThunk;
    } IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
      WORD Hint;
      CHAR Name[1];
    } IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_BASE_RELOCATION {
      DWORD VirtualAddress;
      DWORD SizeOfBlock;
    } IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_SECTION_HEADER {
      BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
      union {
	DWORD PhysicalAddress;
	DWORD VirtualSize;
      } Misc;
      DWORD VirtualAddress;
      DWORD SizeOfRawData;
      DWORD PointerToRawData;
      DWORD PointerToRelocations;
      DWORD PointerToLinenumbers;
      WORD NumberOfRelocations;
      WORD NumberOfLinenumbers;
      DWORD Characteristics;
    } IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;

#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER) ((ULONG_PTR)ntheader + FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader) + ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))
