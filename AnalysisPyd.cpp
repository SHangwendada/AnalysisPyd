#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// PE �ļ��ṹ����
typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

// ����Ŀ¼�ṹ
typedef struct _IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

// RVA ת�ļ�ƫ��
uint32_t RvaToOffset(uint32_t rva, PIMAGE_SECTION_HEADER sections, uint16_t numSections) {
    for (uint16_t i = 0; i < numSections; i++) {
        if (rva >= sections[i].VirtualAddress && 
            rva < sections[i].VirtualAddress + sections[i].VirtualSize) {
            return sections[i].PointerToRawData + (rva - sections[i].VirtualAddress);
        }
    }
    return 0; // δ�ҵ���Ӧ����
}

// ��������Ŀ¼
void ParseExportDirectory(const uint8_t* peData, PIMAGE_EXPORT_DIRECTORY exportDir, 
                          PIMAGE_SECTION_HEADER sections, uint16_t numSections) {
    // ��ӡģ������
    uint32_t nameOffset = RvaToOffset(exportDir->Name, sections, numSections);
    if (nameOffset == 0) {
        printf("[!] Invalid module name RVA: 0x%08X\n", exportDir->Name);
        return;
    }
    printf("[+] Module Name: %s\n", peData + nameOffset);

    // ��ȡ�����ؼ����������ƫ��
    uint32_t funcArrayOffset = RvaToOffset(exportDir->AddressOfFunctions, sections, numSections);
    uint32_t nameArrayOffset = RvaToOffset(exportDir->AddressOfNames, sections, numSections);
    uint32_t ordinalArrayOffset = RvaToOffset(exportDir->AddressOfNameOrdinals, sections, numSections);

    if (!funcArrayOffset || !nameArrayOffset || !ordinalArrayOffset) {
        printf("[!] Invalid export directory array RVAs\n");
        return;
    }

    // ��ȡ����ָ��
    uint32_t* funcRvas = (uint32_t*)(peData + funcArrayOffset);
    uint32_t* nameRvas = (uint32_t*)(peData + nameArrayOffset);
    uint16_t* ordinals = (uint16_t*)(peData + ordinalArrayOffset);

    // �������е�������
    printf("[+] Exported Functions (%d):\n", exportDir->NumberOfNames);
    for (uint32_t i = 0; i < exportDir->NumberOfNames; i++) {
        // ��ȡ��������
        uint32_t nameRva = nameRvas[i];
        uint32_t nameOffset = RvaToOffset(nameRva, sections, numSections);
        if (nameOffset == 0) {
            printf("[!] Invalid function name RVA: 0x%08X\n", nameRva);
            continue;
        }
        const char* funcName = (const char*)(peData + nameOffset);

        // ��ȡ��������������ʵ������
        uint16_t ordinalIndex = ordinals[i];
        if (ordinalIndex >= exportDir->NumberOfFunctions) {
            printf("[!] Invalid ordinal index: %d\n", ordinalIndex);
            continue;
        }
        uint32_t funcRva = funcRvas[ordinalIndex];
        uint32_t funcOffset = RvaToOffset(funcRva, sections, numSections);

        // �����Ϣ
        printf("  %-30s Ordinal: %-4d RVA: 0x%08X Offset: 0x%08X\n",
               funcName, exportDir->Base + ordinalIndex, funcRva, funcOffset);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PE file>\n", argv[0]);
        return 1;
    }

    // ���ļ�
    FILE* file = fopen(argv[1], "rb");
    if (!file) {
        perror("[-] Failed to open file");
        return 1;
    }

    // ��ȡ DOS ͷ
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, file) != 1) {
        perror("[-] Failed to read DOS header");
        fclose(file);
        return 1;
    }

    // ��� DOS ǩ�� "MZ"
    if (dosHeader.e_magic != 0x5A4D) {
        printf("[-] Invalid DOS signature\n");
        fclose(file);
        return 1;
    }

    // ��λ NT ͷ
    fseek(file, dosHeader.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS64 ntHeaders;
    if (fread(&ntHeaders, sizeof(ntHeaders), 1, file) != 1) {
        perror("[-] Failed to read NT headers");
        fclose(file);
        return 1;
    }

    // ��� PE ǩ�� "PE\0\0"
    if (ntHeaders.Signature != 0x00004550) {
        printf("[-] Invalid PE signature\n");
        fclose(file);
        return 1;
    }

    // ��ȡ����ͷ
    uint16_t numSections = ntHeaders.FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)malloc(numSections * sizeof(IMAGE_SECTION_HEADER));
    fseek(file, dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64), SEEK_SET);
    if (fread(sections, sizeof(IMAGE_SECTION_HEADER), numSections, file) != numSections) {
        perror("[-] Failed to read section headers");
        free(sections);
        fclose(file);
        return 1;
    }

    // ��鵼��Ŀ¼�Ƿ����
    IMAGE_DATA_DIRECTORY exportDirEntry = ntHeaders.OptionalHeader.DataDirectory[0];
    if (exportDirEntry.VirtualAddress == 0 || exportDirEntry.Size == 0) {
        printf("[-] No export directory found\n");
        free(sections);
        fclose(file);
        return 1;
    }

    // ��ȡ�����ļ����ڴ�
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t* peData = (uint8_t*)malloc(fileSize);
    if (fread(peData, 1, fileSize, file) != fileSize) {
        perror("[-] Failed to read file into memory");
        free(peData);
        free(sections);
        fclose(file);
        return 1;
    }
    fclose(file);

    // ��λ����Ŀ¼
    uint32_t exportDirOffset = RvaToOffset(exportDirEntry.VirtualAddress, sections, numSections);
    if (exportDirOffset == 0) {
        printf("[-] Failed to locate export directory\n");
        free(peData);
        free(sections);
        return 1;
    }

    IMAGE_EXPORT_DIRECTORY exportDir;
    memcpy(&exportDir, peData + exportDirOffset, sizeof(exportDir));

    // ��������Ŀ¼
    ParseExportDirectory(peData, &exportDir, sections, numSections);

    // ������Դ
    free(peData);
    free(sections);
    return 0;
}
