#include <iostream>
#include <conio.h>
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <string>

#include "PE.h"


//load file to pares
void E_File::LoadFile(std::string path)
{
	Hanlde_Of_File = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (Hanlde_Of_File == INVALID_HANDLE_VALUE)
	{
		printf("CreateFile did not worked \n");
	}
	else
		printf("CreateFile worked successfully \n");
}

//mapping opened file in to the RAM
void E_File::MapFile()
{
	Hanlde_Of_FileMapping = CreateFileMapping(Hanlde_Of_File, NULL, PAGE_READONLY, 0, 0, NULL);
	if (Hanlde_Of_FileMapping == 0)
	{
		printf("CreateFileMapping did not worked \n");
		CloseHandle(Hanlde_Of_File);
	}
	else
		printf("CreateFileMapping worked successfully \n");
}

//findn starting address of the mapped view in the RAM
void E_File::FindStartingAddressOfTheMappedView()
{
	Lp_Of_FileBase = MapViewOfFile(Hanlde_Of_FileMapping, FILE_MAP_READ, 0, 0, 0);
	if (Lp_Of_FileBase == 0)
	{
		printf("MapViewOfFile did not work \n");
		CloseHandle(Hanlde_Of_FileMapping);
		CloseHandle(Hanlde_Of_File);
	}
	else
		printf("MapViewOfFile worked successfully \n");
}

//initilze dos header, dos header contains first 64bytes of exe file
void E_File::SetDosHeader()
{
	DosHeader_Of_File = (PIMAGE_DOS_HEADER)Lp_Of_FileBase;
}

// now to check if a file is exe we search for the letters "MZ" for Mark Zbikowsky one of the srcinal architects of MS - DOS which is the 2 first bytes of file
bool E_File::IsExe()
{
	if (DosHeader_Of_File->e_magic == IMAGE_DOS_SIGNATURE)
	{
		printf("DOS Signature (MZ) Matched \n");
		return true;
	}
	else
	{
		printf("DOS Signature (MZ) Not Matched \n");
		UnmapViewOfFile(Lp_Of_FileBase);
		CloseHandle(Hanlde_Of_FileMapping);
		CloseHandle(Hanlde_Of_File);
		return false;
	}
}

//to set pe header we need it is offset which is at the 4 last bytes of the dos header then using the starting addres of loeaded
//file in RAM , adding this pointer to this will point to the PE header file
void E_File::SetPeHeader()
{
	PeHeader_Of_file = (PIMAGE_NT_HEADERS)((u_char*)DosHeader_Of_File + DosHeader_Of_File->e_lfanew);
}