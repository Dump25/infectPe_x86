#pragma once
#include <stdio.h>
#include <windows.h>
//#include <conio.h>
#include "PE.h"
//#include <iostream>
#pragma warning(disable : 4996)

typedef struct
{
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNtHeaders;
	PIMAGE_SECTION_HEADER	pSectionHeader[100];

	CHAR	   				*dwDosStup;
	DWORD					dwSectionCount;
	DWORD					dwImage;
	DWORD					dwImageSizeOnDisk;
} PE_Info;

union HexToChar
{
	unsigned int twoChar;
	unsigned char character[2];
};

void changEntryPoint(PE_Info *);
void writeToFile(PE_Info );
void init(FILE *, PE_Info *);
void disableASLR(PE_Info *);
void addSection(int, PE_Info, PE_Info *, IMAGE_SECTION_HEADER *);
