/*
A simple PE parser . It recognizes if the PE file is a 32 or 64 bits and prints out the import table.
*/


#include <stdio.h>
//#include "nttypes.h"
//#include "ntstructs.h"
#include <windows.h>


int main(int argc, char* argv[]){

    LPSTR FileName = argv[1];
    printf("[#] Proccessing the PE file \t%s\n",FileName);
    DWORD size;
    HANDLE hPE_image;
    /*
    HANDLE CreateFileA(
    [in]           LPCSTR                lpFileName,
    [in]           DWORD                 dwDesiredAccess,
    [in]           DWORD                 dwShareMode,
    [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    [in]           DWORD                 dwCreationDisposition,
    [in]           DWORD                 dwFlagsAndAttributes,
    [in, optional] HANDLE                hTemplateFile
    );
    */

    hPE_image = CreateFileA(FileName , GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL) ;
    
    if (hPE_image == NULL){
        
        printf("[!]CREATE ERROR : %d",GetLastError);
        return 1;
    }

    size = GetFileSize(hPE_image, NULL);

    if (size == INVALID_FILE_SIZE){
        
        printf(" [!]SIZE Error : %ld ", GetLastError());
        CloseHandle(hPE_image);
        return 1;
    }

    /*
    BOOL ReadFile(
    [in]                HANDLE       hFile,
    [out]               LPVOID       lpBuffer,
    [in]                DWORD        nNumberOfBytesToRead,
    [out, optional]     LPDWORD      lpNumberOfBytesRead,
    [in, out, optional] LPOVERLAPPED lpOverlapped
    );
    */

   BYTE PE_image[size];
   
   if (!ReadFile(hPE_image, &PE_image , size, NULL, NULL)){
    
    printf("[!]READ Error : %ld" , GetLastError());
    CloseHandle(hPE_image);
    return 1;
   }

    printf("[#]Read file with size %ld\n",size);
    CloseHandle(hPE_image);

    IMAGE_DOS_HEADER* DosHdr = (PIMAGE_DOS_HEADER) &PE_image;
    
    if (!DosHdr->e_magic == IMAGE_DOS_SIGNATURE){
        
        printf("[!]PE file does not contain a DOS Signature" );
    }
    
    IMAGE_NT_HEADERS* nt_Headers = (PIMAGE_NT_HEADERS)((BYTE*)PE_image+DosHdr->e_lfanew);

    if (nt_Headers->Signature != IMAGE_NT_SIGNATURE){ //0x00004550
        printf("PE Signature not found in the image file");
        return 1;
    }
    
    printf("[#] PE_Signature found \t %4x\n[#] Continuing\n", nt_Headers->Signature );

    WORD magic = nt_Headers->OptionalHeader.Magic ;

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC){

        printf("[*]The image file is PE32+\n");
    }
    else{
        printf("[*]The image is PE32\n");
    }

    
    // Mapping the PE file manually to memory in order to work with virtuall addresses 

    /*
    LPVOID VirtualAlloc(
        [in, optional] LPVOID lpAddress,
        [in]           SIZE_T dwSize,
        [in]           DWORD  flAllocationType,
        [in]           DWORD  flProtect
    );
    */
    BYTE* image = VirtualAlloc(NULL, nt_Headers->OptionalHeader.SizeOfImage , MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    memcpy(image , PE_image , nt_Headers->OptionalHeader.SizeOfHeaders);
    //First section header
    IMAGE_SECTION_HEADER* Section_Header = (IMAGE_SECTION_HEADER*) IMAGE_FIRST_SECTION(nt_Headers);
    //OR 
    //IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (nt_Headers + 1);
    for (int i=0 ; i < nt_Headers->FileHeader.NumberOfSections; i++){
        
    if (Section_Header[i].SizeOfRawData >0){
        memcpy((BYTE*)image + Section_Header[i].VirtualAddress , PE_image + Section_Header[i].PointerToRawData , Section_Header[i].SizeOfRawData);
    }
    
    }
    

    
    IMAGE_DATA_DIRECTORY importsDirectory = nt_Headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC){

        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (ULONG_PTR)image );
        while ( importDescriptor->Name != NULL){ // import entry table zeroed out -> thats all dll`s
            LPCSTR libraryName =(LPCSTR) importDescriptor->Name + (ULONG_PTR)image;
            HMODULE library = LoadLibraryA(libraryName);
            printf("DLL NAME :  %s\n", libraryName);
            PIMAGE_THUNK_DATA64  thunk = (PIMAGE_THUNK_DATA64)((ULONG_PTR)image + importDescriptor->FirstThunk);
            while (thunk->u1.AddressOfData != NULL){ //ILT zeroed out -> end of table
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)){
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL64(thunk->u1.Ordinal);
                    ULONG_PTR functionAddress = (ULONG_PTR)(GetProcAddress(library, functionOrdinal));
                    printf("\t FuncAddress : %s\n", functionAddress);

                }else{
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)image + thunk->u1.AddressOfData);
                    printf("\t FuncName : %s\n", functionName);
                }
            
            thunk++;
            }
        importDescriptor++;
        }
    }
    else{
        PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)image );
        while ( importDescriptor->Name != NULL){ // import entry table zeroed out -> thats all dll`s
            LPCSTR libraryName =(LPCSTR) importDescriptor->Name + (DWORD_PTR)image;
            HMODULE library = LoadLibraryA(libraryName);
            printf("DLL NAME :  %s\n", libraryName);
            PIMAGE_THUNK_DATA32  thunk = (PIMAGE_THUNK_DATA32)((DWORD_PTR)image + importDescriptor->FirstThunk);
            while (thunk->u1.AddressOfData != NULL){ //ILT zeroed out -> end of table
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)){
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL32(thunk->u1.Ordinal);
                    ULONG_PTR functionAddress = (DWORD_PTR)(GetProcAddress(library, functionOrdinal));
                    printf("\t FuncAddress : %s\n", functionAddress);

                }else{
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)image + thunk->u1.AddressOfData);
                    printf("\t FuncName : %s\n", functionName);
                }
            
            thunk++;
            }
        importDescriptor++;

    }

    }

    VirtualFree(image,0,MEM_RELEASE);

    return 0;
}

