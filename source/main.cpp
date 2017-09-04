#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "windows.h"
#include <winternl.h>
#include <intrin.h>

//#define _BUILD_FOR_WINXP_X86

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

static __declspec(naked) NTSTATUS __stdcall NtVirtualQuery(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
{
	__asm{
		call next
		ret 0x18
next:
#ifdef _BUILD_FOR_WINXP_X86
		mov eax, 0x0B2
#else
		mov eax, 0x10B
#endif
		mov edx, esp
	   _emit 0x0F
	   _emit 0x34
	   ret 0x18
	};

}

static __declspec(naked) NTSTATUS __stdcall NtVirtualProtect(HANDLE hProcess, LPVOID lpAddress, SIZE_T* pdwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	__asm{
		call next
		ret 0x14
next:
#ifdef _BUILD_FOR_WINXP_X86
		mov eax, 0x89
#else
		mov eax, 0x0d7
#endif
		mov edx, esp
	   _emit 0x0F
	   _emit 0x34
	   ret 0x14
	};
}

static __declspec(naked) NTSTATUS __stdcall hook_NtAllocateVirtualMemory(HANDLE ProcessHandle,PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	__asm {  
      push ebp  
      mov ebp, esp
	};

	if(ProcessHandle == (HANDLE)-1)
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
	}
	SKIP:
	__asm{
		mov esp, ebp
		pop ebp 
		call next 
		ret 0x18
next:
#ifdef _BUILD_FOR_WINXP_X86
		mov eax, 0x11
#else
		mov eax, 0x13
#endif
		mov edx, esp
	   _emit 0x0F
	   _emit 0x34
	   ret 0x18
	};
}

static __declspec(naked) NTSTATUS __stdcall hook_NtVirtualProtect(HANDLE hProcess, LPVOID* lpAddress, SIZE_T* pdwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	__asm {  
      push ebp  
      mov ebp, esp
	};

	if(hProcess == (HANDLE)-1)
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
	SKIP:
	__asm{
		mov esp, ebp
		pop ebp
		call next
		ret 0x14
next:
#ifdef _BUILD_FOR_WINXP_X86
		mov eax, 0x89
#else
		mov eax, 0x0d7
#endif
		mov edx, esp
	   _emit 0x0F
	   _emit 0x34
	   ret 0x14
	};
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

static __declspec(naked) NTSTATUS __stdcall hook_NtMapViewofSection(
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
	__asm{
		call next
		push [esp+0xc] //*base
		push [esp+0xc] //processhandle
		push eax       //status
		call DoImg
		ret 0x28
next:
#ifdef _BUILD_FOR_WINXP_X86
		mov eax, 0x6C
#else
		mov eax, 0x0A8
#endif
		mov edx, esp
	   _emit 0x0F
	   _emit 0x34
	   ret 0x28
	};
}

void SetHooks()
{
	DWORD Old_Protect=NULL,temp=NULL;
	MEMORY_BASIC_INFORMATION mbi = {0};

	DWORD *lpNtProtectVirtMem = (DWORD*) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"NtProtectVirtualMemory");
	if(lpNtProtectVirtMem)
	{
		NtVirtualQuery((HANDLE)-1,lpNtProtectVirtMem,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
		NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
		*(DWORD*)((DWORD)lpNtProtectVirtMem+1) = ( (DWORD)&hook_NtVirtualProtect - ((DWORD)lpNtProtectVirtMem+5) );
		*((char*)lpNtProtectVirtMem) = (char)0xe9;
		NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);
	}

	DWORD *lpNtAllocateVirtMem = (DWORD*) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"NtAllocateVirtualMemory");
	if(lpNtAllocateVirtMem)
	{
		NtVirtualQuery((HANDLE)-1,lpNtAllocateVirtMem,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
		NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
		*(DWORD*)((DWORD)lpNtAllocateVirtMem+1) = ( (DWORD)&hook_NtAllocateVirtualMemory - ((DWORD)lpNtAllocateVirtMem+5) );
		*((char*)lpNtAllocateVirtMem) = (char)0xe9;
		NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);
	}
	
	DWORD *lpNtmapViewOfSection = (DWORD*) GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")),"NtMapViewOfSection");
	if(lpNtmapViewOfSection)
	{
		NtVirtualQuery((HANDLE)-1,lpNtmapViewOfSection,MemoryBasicInformation,&mbi,sizeof(mbi),NULL);
		NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),PAGE_EXECUTE_READWRITE,&Old_Protect);
		*(DWORD*)((DWORD)lpNtmapViewOfSection+1) = ( (DWORD)&hook_NtMapViewofSection - ((DWORD)lpNtmapViewOfSection+5) );
		*((char*)lpNtmapViewOfSection) = (char)0xe9;
		NtVirtualProtect((HANDLE)-1,&(mbi.BaseAddress),&(mbi.RegionSize),Old_Protect,&temp);
	}
	
}