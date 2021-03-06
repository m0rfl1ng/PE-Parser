#include <iostream>
#include <conio.h>
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <string>

#pragma once
#ifndef PE
#define PE

class E_File {

private:
	LPCSTR FileName;
	HANDLE Hanlde_Of_File = NULL;
	HANDLE Hanlde_Of_FileMapping = NULL;
	LPVOID Lp_Of_FileBase = NULL;
	PIMAGE_DOS_HEADER DosHeader_Of_File;
	//PIMAGE_NT_HEADERS PeHeader_Of_file;
	PIMAGE_NT_HEADERS64 PeHeader_Of_file;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
	IMAGE_FILE_HEADER Image_Header_Of_File; //the next 20 bytes after pe signature aka  50h, 45h, 00h, 00h
	PIMAGE_SECTION_HEADER Sections_Of_File;

	// Resources section, .rsrc stuct
	PIMAGE_RESOURCE_DIRECTORY Resources_Section; //we will point it to the .rsrc section

public:
	void LoadFile(std::string);
	void MapFile();
	void FindStartingAddressOfTheMappedView();
	void SetDosHeader();
	bool IsExe();
	void SetPeHeader();
	DWORD PeSingnature();
	void SetImageHeader();
	WORD Machine();
	WORD MagicValue();
	WORD NumberOfSections();
	DWORD SizeOfImage();
	DWORD SizeOfOptionalHeader();
	ULONGLONG ImageBase();
	void FetchSectionsOfFile();
	void FetchResourceDirectory();
};

#endif
