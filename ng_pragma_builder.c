// ng_pragma_builder.cpp : Defines the entry point for the console application.
//

#include "pragma.h"

BOOLEAN Is32Bit;
CHAR DllName [MAX_PATH];

void ParseExportTable(ULONG_PTR Address, DWORD ExportTableRawToRVAOffset, DWORD ExportTableSize, FILE* Dll, FILE* Pragma)
/*
   Here, we have to keep tabs on two different tables:
   -The export name string pointer table, from which the names will be extracted. Each entry is tied to a "named ordinal"
   entry in a separate table, which is the function's real ordinal minus the ordinal bias (IMAGE_EXPORT_DIRECTORY->Bias).
   However, that ordinal table is out of order and excludes unnamed exports.
   -The main table of export table function pointers. They are arranged in terms of ordinal, and in the event of ordinal
   values being skipped, the function pointer is NULL.

   Because of the odd nature of the named export-related tables, an array of ordinal entries will be created: the value of
   IMPORT_EXPORT_DIRECTORY->NumberOfFunctions*sizeof(BOOLEAN) (which is a byte) long. If an ordinal value is encountered
   in the first table, its value is set to TRUE in the array. Once all named exports and corresponding ordinals have been taken into
   account, a second iteration through the export function pointer table will take place; if an ordinal value is not associated with
   a named export and its function pointer is not NULL, it will also be written to the pragma file.
*/
{
	int i;
	ULONG* FunctionPtr;
	USHORT* NamedOrdinals;
	ULONG* NamePtr;
	CHAR* FunctionName;
	PVOID ExportTableBuffer = malloc(ExportTableSize);
	fseek(Dll, Address - ExportTableRawToRVAOffset, SEEK_SET);
	fread(ExportTableBuffer, ExportTableSize, 1, Dll);
	IMAGE_EXPORT_DIRECTORY* ExportDirectory = ExportTableBuffer;
	BYTE* ByteMap = ExportTableBuffer;
	NamedOrdinals = &ByteMap[ExportDirectory->AddressOfNameOrdinals - Address];
	NamePtr = &ByteMap[ExportDirectory->AddressOfNames - Address];
	FunctionPtr = &ByteMap[ExportDirectory->AddressOfFunctions - Address];
	BOOLEAN* IsOrdinalNamed = malloc(sizeof(BOOLEAN)*ExportDirectory->NumberOfFunctions);
	RtlZeroMemory(IsOrdinalNamed, sizeof(BOOLEAN)*ExportDirectory->NumberOfFunctions);
	USHORT Ordinal;

	for(i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
		FunctionName = &ByteMap[*NamePtr - Address];
		Ordinal = *NamedOrdinals + ExportDirectory->Base;
		if(FunctionName[0] == '_' && Is32Bit) // The PE32 linker will remove an underscore from a function name if it is present
		fprintf(Pragma, "\n#pragma comment(linker, \"/export:_%s=%s.%s,@%d\")", FunctionName, DllName, FunctionName, Ordinal);
		else
		fprintf(Pragma, "\n#pragma comment(linker, \"/export:%s=%s.%s,@%d\")", FunctionName, DllName, FunctionName, Ordinal);

		IsOrdinalNamed[*NamedOrdinals] = TRUE;
		++NamePtr;
		++NamedOrdinals;
	}
	for(i = 0; i < ExportDirectory->NumberOfFunctions; i++)
	{
		Ordinal = i + ExportDirectory->Base;
		if(!IsOrdinalNamed[i] && *FunctionPtr != 0x0)
		{
			fprintf(Pragma, "\n#pragma comment(linker, \"/export:%d=%s.#%d,@%d,NONAME\")", Ordinal, DllName, Ordinal, Ordinal);
		}
		++FunctionPtr;
	}

}

int _tmain(int argc, _TCHAR* argv[])
{
	IMAGE_NT_HEADERS32* Header;
	CHAR DllPath [MAX_PATH];
	CHAR PragmaPath [MAX_PATH];
	HEADER FileBegin;
	SECTIONENTRY* Section;
	DWORD NumberOfSections;
	int i;
	ULONG_PTR HeaderOffset;
	ULONG_PTR SectionOffset;
	ULONG_PTR ExportTableRVA;
	DWORD ExportTableRawToRVAOffset;
	DWORD ExportTableSize;
	PVOID SectionBuffer;
	BOOLEAN IsPESignaturePresent = FALSE;
	FILE* Dll;
	FILE* Pragma;

	i = 0;
	if(argc == 4)
	{
	while(argv[1][i] != '\0' && i < MAX_PATH)
	{
	DllPath[i] = argv[1][i];
	i++;
	}
	DllPath[i] = '\0';
	i = 0;
	while(argv[2][i] != '\0' && i < MAX_PATH)
	{
	PragmaPath[i] = argv[2][i];
	i++;
	}
	PragmaPath[i] = '\0';
	i = 0;
	while(argv[3][i] != '\0' && i < MAX_PATH)
	{
	DllName[i] = argv[3][i];
	i++;
	}
	DllName[i] = '\0';
	}
	else
	{
		printf("Enter the path of your target PE image.\n");
		scanf("%s", DllPath);

		printf("\nEnter the name of the pragma file you want to create.\n");
		scanf("%s", PragmaPath);
		printf("\nEnter the name of the PE image you want to forward towards.\n");
		scanf("%s", DllName);
	}
	/*
	   Instead of loading the PE images directly into memory via LdrLoadDll or similar which only works well for images of
	   the same architecture, I read them as data files and look for the signatures and "Magic" values manually.
	*/

	/* Warning for WOW64 users: WOW64 file redirection will prevent you from loading x64 DLLs from your %windir%\system32.
       I wanted to build only for x86 but GetProcAddress-ing the WOW64 file system redirection toggling functions failed.
	   So I decided to build both x86 and AMD64 binaries.
    */
	Dll = fopen(DllPath, "rb");

	if(!Dll)
	{
		printf("\nImage could not be opened or found. Try again.\n");
        return -1;
	}

	Pragma = fopen(PragmaPath, "w");

	if(!Pragma)
	{
		printf("\nUnable to open or create pragma file. Try again.\n");
		return -1;
	}

	fseek(Dll, 0x40, SEEK_SET);
	fread(&FileBegin, 200*sizeof(USHORT), 1, Dll);
    
	for(i = 0; i < 199; i++)
	{
	//	printf("\n0x%x at 0x%x", FileBegin.Members[i], (i*2 + 0x40));
		if(FileBegin.Members[i] == 0x4550 && FileBegin.Members[i + 1] == 0)
		{
			IsPESignaturePresent = TRUE;
			HeaderOffset = i*2 + 0x40;
			break;
		}
	}
	if(!IsPESignaturePresent)
	{
		printf("\nImage is not a Portable Executable. Try again.\n");
        return -1;
	}

	fseek(Dll, HeaderOffset, SEEK_SET);

	Header = malloc(sizeof(IMAGE_NT_HEADERS64));

	fread(Header, sizeof(IMAGE_NT_HEADERS64), 1, Dll);

	if(Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		Is32Bit = TRUE;
	else if(Header->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        Is32Bit = FALSE;
	else
	{
		printf("\nUnable to confirm bitness of PE image, assuming 32 bit.\n");
	}

	if(Is32Bit)
		SectionOffset = HeaderOffset + sizeof(IMAGE_NT_HEADERS32);
	else
        SectionOffset = HeaderOffset + sizeof(IMAGE_NT_HEADERS64);

	IMAGE_NT_HEADERS64* Header64 = Header;
    if(Is32Bit)
	{
		if(!Header->OptionalHeader.DataDirectory[0].Size)
		{
		   printf("\nThere is no export table in this PE image. Try again.\n");
		   return -1;
		}
		else
        ExportTableSize = Header->OptionalHeader.DataDirectory[0].Size;
	}
	else
	{
		if(!Header64->OptionalHeader.DataDirectory[0].Size)
		{
		   printf("\nThere is no export table in this PE image. Try again.\n");
		   return -1;
		}
		else
        ExportTableSize = Header64->OptionalHeader.DataDirectory[0].Size;
	}

	fprintf(Pragma, "// This is an automatically-generated pragma file for your wrapper DLL for your OpenNT project.\n\n");

	if(Is32Bit)
		fprintf(Pragma, "#pragma comment(linker, \"/BASE:0x%x\")", Header->OptionalHeader.ImageBase);
	else
		fprintf(Pragma, "#pragma comment(linker, \"/BASE:0x%I64x\")", Header64->OptionalHeader.ImageBase);

    Section = SectionOffset;

	NumberOfSections = Header->FileHeader.NumberOfSections;

	SectionBuffer = malloc(NumberOfSections*sizeof(SECTIONENTRY));

	fseek(Dll, SectionOffset, SEEK_SET);
	fread(SectionBuffer, NumberOfSections*sizeof(SECTIONENTRY), 1, Dll);
	Section = SectionBuffer;
	if(Is32Bit)
	ExportTableRVA = Header->OptionalHeader.DataDirectory[0].VirtualAddress;
	else
	ExportTableRVA = Header64->OptionalHeader.DataDirectory[0].VirtualAddress;

	/*
	   Before referencing the deeper parts of the struct that diverge between native word sizes due to pointer usage,  
       the bitness of the PE image is determined; this will be important, not only due to differing offsets, but also to deal
	   with 32 bit linker semantics.

	   Now, we have to convert the RVAs referenced in the header structures to raw addresses as these PE images
	   are not loaded in memory. We will have to parse every section and its specified RVAs and sizes to determine
	   the raw addresses of the export table and structures.
	*/
	for(i = 0; i < NumberOfSections; i++)
	{
		if(ExportTableRVA >= Section->VirtualAddress && ExportTableRVA < (Section->VirtualAddress + Section->VirtualSize))
		{
			ExportTableRawToRVAOffset = Section->VirtualAddress - Section->RawAddress;
			break;
		}
		Section++;
	}

    ParseExportTable(ExportTableRVA, ExportTableRawToRVAOffset, ExportTableSize, Dll, Pragma);

	return 0;
}

