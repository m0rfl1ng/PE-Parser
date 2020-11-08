#include <iostream>
#include <conio.h>
#include <stdlib.h>
#include <stdio.h>
#include <Windows.h>
#include <string>

#include "PE.h"

int main()
{
	E_File TestFile;
	TestFile.LoadFile("x");
	TestFile.MapFile();
	TestFile.FindStartingAddressOfTheMappedView();
	TestFile.SetDosHeader();
	if (TestFile.IsExe())
	{
		TestFile.SetPeHeader();
	}

	return 0;
}