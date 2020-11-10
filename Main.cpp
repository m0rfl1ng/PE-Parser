#include <iostream>
#include <conio.h>
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <string>

#include "PE.h"

int main()
{
	std::cout << "Begin: " << std::endl;
	E_File TestFile;
	TestFile.LoadFile(x);
	TestFile.MapFile();
	TestFile.FindStartingAddressOfTheMappedView();
	TestFile.SetDosHeader();
	if (TestFile.IsExe())
	{
		TestFile.SetPeHeader();
		std::cout << "PE signature: " << TestFile.PeSingnature() << std::endl;
		std::cout << "Magic number: " << TestFile.MagicValue() << std::endl;
		TestFile.SetImageHeader();
		std::cout << "Macine value: " << TestFile.Machine() << std::endl;
		std::cout << "Number of sections: " << TestFile.NumberOfSections() << std::endl;
		std::cout << "Size of optional header: " << TestFile.SizeOfOptionalHeader() << std::endl;
		std::cout << "Size of Image: " << TestFile.SizeOfImage() << std::endl;
		TestFile.FetchSectionsOfFile();
	}

	return 0;
}
