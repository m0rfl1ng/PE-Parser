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

// extracting PE singnature at te start of PE header which is equal to 50h, 45h, 00h, 00h
DWORD E_File::PeSingnature()
{
	return PeHeader_Of_file->Signature;
}

//set image header of file
void E_File::SetImageHeader()
{
	Image_Header_Of_File = PeHeader_Of_file->FileHeader;
}


//return the value of machine which defines the exe file can run on which typte of machhines
WORD E_File::Machine()
{
	return Image_Header_Of_File.Machine;
}

// return Magic value of exe file if it is 0x20b then the exe file is x64 bit and if it is 0x10b it is x32 bit aka x86
WORD E_File::MagicValue()
{
	return PeHeader_Of_file->OptionalHeader.Magic;
}

//retun number of sections in the exe file
WORD E_File::NumberOfSections()
{
	return Image_Header_Of_File.NumberOfSections;
}

//retun size of image
DWORD E_File::SizeOfImage()
{
	return PeHeader_Of_file->OptionalHeader.SizeOfImage;
}

//The size of the optional header, which is required for executable files but not for object files.
DWORD E_File::SizeOfOptionalHeader()
{
	return Image_Header_Of_File.SizeOfOptionalHeader;
}

//section header offset is  dosheader+dosstub+peheader aka starting offset + e_lfanew + 4bytes(pe signature) + 20bytes(file header) + sizeof(optionalheader)
void E_File::FetchSectionsOfFile()
{
	Sections_Of_File = (PIMAGE_SECTION_HEADER)((u_char*)DosHeader_Of_File + DosHeader_Of_File->e_lfanew + Image_Header_Of_File.SizeOfOptionalHeader + (u_char)24);
	std::cout << Sections_Of_File << std::endl;
	int i = 1;
	for (i; i <= Image_Header_Of_File.NumberOfSections; i++)
	{
		std::cout << "***************************" << std::endl;
		std::cout << "Name of section: " << Sections_Of_File->Name << std::endl;
		std::cout << "VirtualAddress of section: " << Sections_Of_File->VirtualAddress << std::endl;
		std::cout << "Characteristics of section: " << Sections_Of_File->Characteristics << std::endl;
		std::cout << "PointerToRawData of section: " << Sections_Of_File->PointerToRawData << std::endl;
		std::cout << "SizeOfRawData of section: " << Sections_Of_File->SizeOfRawData << std::endl;
		Sections_Of_File = (PIMAGE_SECTION_HEADER)((u_char*)DosHeader_Of_File + DosHeader_Of_File->e_lfanew + Image_Header_Of_File.SizeOfOptionalHeader + (u_char)24 + (u_char)(40 * i));
	}
}
