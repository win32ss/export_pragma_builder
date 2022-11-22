#pragma once

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <winternl.h>

IMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
NTSYSAPI NTSTATUS NTAPI LdrLoadDll(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);
typedef BOOLEAN (*Wow64FsRedir)(BOOLEAN);

typedef struct Header{
	USHORT Members [200];
}HEADER, *PHEADER;

typedef struct SECTIONENTRY{
	CHAR SectionName[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
	DWORD RawSize;
	DWORD RawAddress;
	DWORD RelocAddress;
	DWORD LineNumbers;
	WORD Relocs;
	WORD Lines;
	DWORD SectionFlags;
}SECTIONENTRY, *PSECTIONENTRY;
