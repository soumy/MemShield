#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "windows.h"
#include <winternl.h>
#include <intrin.h>

void SetHooks();

BOOL WINAPI DllMain(_In_  HINSTANCE hinstDLL,_In_  DWORD fdwReason,_In_  LPVOID lpvReserved)
{
	HMODULE module = NULL;
	switch ( fdwReason )
	{
	case DLL_PROCESS_ATTACH:
		{

			//We do not need thread callbacks
			DisableThreadLibraryCalls( hinstDLL );
			//Lock ourself in mem
			GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,(LPCTSTR)hinstDLL,&module);
			//Enable DEP permanently
			SetProcessDEPPolicy(PROCESS_DEP_ENABLE);
			//Put our hooks
			SetHooks();
		}
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

typedef enum _MEMORY_INFORMATION_CLASS { 
  MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS (__stdcall *MyNtVirtualQuery)(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
static MyNtVirtualQuery NtVirtualQuery = NULL;

typedef NTSTATUS (__stdcall *MyNtVirtualProtect_Type)(HANDLE hProcess, LPVOID lpAddress, SIZE_T* pdwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
MyNtVirtualProtect_Type MyNtVirtualProtect = NULL;

#define NOP  __nop();
#define NOPS NOP NOP NOP NOP NOP NOP NOP NOP NOP NOP
#define NOPSLIDE NOPS NOPS NOPS NOPS NOPS

static NTSTATUS __stdcall NtVirtualProtect(HANDLE hProcess, LPVOID lpAddress, SIZE_T* pdwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	NOPSLIDE;
	return ERROR_SUCCESS;
}

static NTSTATUS __stdcall NtAllocateVirtualMemory(HANDLE ProcessHandle,PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	NOPSLIDE;
	return ERROR_SUCCESS;
}

static NTSTATUS __stdcall hook_NtAllocateVirtualMemory(HANDLE ProcessHandle,PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	if(Protect & PAGE_EXECUTE)
	{
		Protect &= ~PAGE_EXECUTE;
		Protect |= PAGE_READONLY;
	}
	if(Protect & PAGE_EXECUTE_READ)
	{
		Protect &= ~PAGE_EXECUTE_READ;
		Protect |= PAGE_READONLY; 
	}
	if(Protect & PAGE_EXECUTE_READWRITE)
	{
		Protect &= ~PAGE_EXECUTE_READWRITE;
		Protect |= PAGE_READWRITE;
	}
	if(Protect & PAGE_EXECUTE_WRITECOPY)
	{
		Protect &= ~PAGE_EXECUTE_WRITECOPY;
		Protect |= PAGE_WRITECOPY;
	}
	return NtAllocateVirtualMemory(ProcessHandle,BaseAddress,ZeroBits,RegionSize,AllocationType,Protect);
}

static int stack_space = sizeof(MEMORY_BASIC_INFORMATION) + sizeof(PVOID);
static NTSTATUS __stdcall hook_NtVirtualProtect(HANDLE hProcess, LPVOID* lpAddress, SIZE_T* pdwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	MEMORY_BASIC_INFORMATION gmbi;
	memset(&gmbi,0,sizeof(MEMORY_BASIC_INFORMATION));
	NtVirtualQuery((HANDLE)-1,*lpAddress,MemoryBasicInformation,&gmbi,sizeof(MEMORY_BASIC_INFORMATION),NULL);
	
	if((gmbi.Type&MEM_IMAGE))
	{
		
		if(flNewProtect & PAGE_EXECUTE_READWRITE)
		{
			flNewProtect &= ~PAGE_EXECUTE_READWRITE;
			flNewProtect |= PAGE_READWRITE;
		}
		if(flNewProtect & PAGE_EXECUTE_WRITECOPY)
		{
			flNewProtect &= ~PAGE_EXECUTE_WRITECOPY;
			flNewProtect |= PAGE_WRITECOPY;
		}
		
	}
	else
	{
		if(flNewProtect & PAGE_EXECUTE)
		{
			flNewProtect &= ~PAGE_EXECUTE;
			flNewProtect |= PAGE_READONLY;
		}
		if(flNewProtect & PAGE_EXECUTE_READ)
		{
			flNewProtect &= ~PAGE_EXECUTE_READ;
			flNewProtect |= PAGE_READONLY; 
		}
		if(flNewProtect & PAGE_EXECUTE_READWRITE)
		{
			flNewProtect &= ~PAGE_EXECUTE_READWRITE;
			flNewProtect |= PAGE_READWRITE;
		}
		if(flNewProtect & PAGE_EXECUTE_WRITECOPY)
		{
			flNewProtect &= ~PAGE_EXECUTE_WRITECOPY;
			flNewProtect |= PAGE_WRITECOPY;
		}
	}
	return NtVirtualProtect(hProcess, lpAddress, pdwSize, flNewProtect, lpflOldProtect);
}

static NTSTATUS __stdcall DoImg(NTSTATUS status, HANDLE ProcessHandle, PVOID *Pbase)
{
	PVOID base = *Pbase;
	if(base && ProcessHandle == (HANDLE) -1)
	{
		MEMORY_BASIC_INFORMATION mbi = {0};
		DWORD Old_Protect,New_Protect;

		NtVirtualQuery((HANDLE)-1,base,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
		if(!(mbi.Type&MEM_IMAGE) || !(mbi.State&MEM_COMMIT)) return status;

		DWORD EntryPoint = ((PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)base)->e_lfanew+(ULONG_PTR)base))->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)base;
		DWORD NSections = ((PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)base)->e_lfanew+(ULONG_PTR)base))->FileHeader.NumberOfSections;

		if(EntryPoint && NSections)
		{
			for(int i = 0 ; i < NSections ; i++)
			{
				PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((((PIMAGE_DOS_HEADER)base)->e_lfanew+(ULONG_PTR)base) + sizeof(IMAGE_NT_HEADERS) + i*sizeof(IMAGE_SECTION_HEADER));
				
				PVOID addr = (PVOID)(section->VirtualAddress + (ULONG_PTR)base);
				VirtualQuery(addr,&mbi,sizeof(mbi));
				if(mbi.Protect & PAGE_EXECUTE_READWRITE)
				{
					NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_READWRITE,&Old_Protect);
					size_t totsize = mbi.RegionSize;
					while(totsize < section->Misc.VirtualSize)
					{
						addr = (PVOID)((ULONG_PTR)mbi.BaseAddress+mbi.RegionSize);
						VirtualQuery(addr,&mbi,sizeof(mbi));
						if((mbi.State&MEM_COMMIT) && (mbi.Type&MEM_IMAGE))
							NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_READWRITE,&Old_Protect);
						else
							break;
						totsize += mbi.RegionSize;
					}
				}
				else if(mbi.Protect & PAGE_EXECUTE_WRITECOPY)
				{
					NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_WRITECOPY,&Old_Protect);
					size_t totsize = mbi.RegionSize;
					while(totsize < section->Misc.VirtualSize)
					{
						addr = (PVOID)((ULONG_PTR)mbi.BaseAddress+mbi.RegionSize);
						VirtualQuery(addr,&mbi,sizeof(mbi));
						if((mbi.State&MEM_COMMIT) && (mbi.Type&MEM_IMAGE))
							NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_WRITECOPY,&Old_Protect);
						else
							break;
						totsize += mbi.RegionSize;
					}
				}
				
			}
		}
	}
	return status;
}

typedef enum _SECTION_INHERIT {
ViewShare = 1,
ViewUnmap = 2
} SECTION_INHERIT;

static NTSTATUS __stdcall NtMapViewofSection(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID           *BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
		  )
{

	NOPSLIDE;
	return ERROR_SUCCESS;
}

static NTSTATUS __stdcall hook_NtMapViewofSection(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID           *BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
		  )
{
	HANDLE processhandle = ProcessHandle;
	PVOID *base = BaseAddress;
	NTSTATUS Status = NtMapViewofSection( SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	return DoImg(Status,processhandle,base);
}

void SetHooks()
{
	DWORD Old_Protect=NULL,temp=NULL;
	MEMORY_BASIC_INFORMATION mbi = {0};

	NtVirtualQuery = (MyNtVirtualQuery) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"NtQueryVirtualMemory");
	PVOID lpNtProtectVirtMem = (PVOID) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"NtProtectVirtualMemory");
	PVOID lpNtAllocateVirtMem = (PVOID) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"NtAllocateVirtualMemory");
	PVOID lpNtmapViewOfSection = (PVOID) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"NtMapViewOfSection");
	

	MyNtVirtualProtect = (MyNtVirtualProtect_Type) lpNtProtectVirtMem;
	if(!NtVirtualQuery || !MyNtVirtualProtect || !lpNtAllocateVirtMem || !lpNtmapViewOfSection) return;

	NtVirtualQuery((HANDLE)-1,&NtVirtualProtect,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
	MyNtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
	memcpy(&NtVirtualProtect,lpNtProtectVirtMem,50);
	MyNtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);

	memset(&mbi,0,sizeof(MEMORY_BASIC_INFORMATION));
	NtVirtualQuery((HANDLE)-1,&NtAllocateVirtualMemory,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
	MyNtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
	memcpy(&NtAllocateVirtualMemory,lpNtAllocateVirtMem,50);
	MyNtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);

	memset(&mbi,0,sizeof(MEMORY_BASIC_INFORMATION));
	NtVirtualQuery((HANDLE)-1,&NtMapViewofSection,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
	MyNtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
	memcpy(&NtMapViewofSection,lpNtmapViewOfSection,50);
	MyNtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);
	
	memset(&mbi,0,sizeof(MEMORY_BASIC_INFORMATION));
	NtVirtualQuery((HANDLE)-1,lpNtAllocateVirtMem,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
	NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
	*(UINT_PTR*)((UINT_PTR)lpNtAllocateVirtMem+1) = ( (UINT_PTR)&hook_NtAllocateVirtualMemory - ((UINT_PTR)lpNtAllocateVirtMem+5) );
	*((char*)lpNtAllocateVirtMem) = (char)0xe9;
	NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);
	
	memset(&mbi,0,sizeof(MEMORY_BASIC_INFORMATION));
	NtVirtualQuery((HANDLE)-1,lpNtProtectVirtMem,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
	NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
	*(UINT_PTR*)((UINT_PTR)lpNtProtectVirtMem+1) = ( (UINT_PTR)&hook_NtVirtualProtect - ((UINT_PTR)lpNtProtectVirtMem+5) );
	*((char*)lpNtProtectVirtMem) = (char)0xe9;
	NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);
	
	memset(&mbi,0,sizeof(MEMORY_BASIC_INFORMATION));
	NtVirtualQuery((HANDLE)-1,lpNtmapViewOfSection,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
	NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
	*(UINT_PTR*)((UINT_PTR)lpNtmapViewOfSection+1) = ( (UINT_PTR)&hook_NtMapViewofSection - ((UINT_PTR)lpNtmapViewOfSection+5) );
	*((char*)lpNtmapViewOfSection) = (char)0xe9;
	NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);
	
	FlushInstructionCache((HANDLE)-1,NULL,0);
}