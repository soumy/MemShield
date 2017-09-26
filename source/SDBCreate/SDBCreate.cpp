#include <windows.h>
#include <stdio.h>
#include <tchar.h>

static TCHAR* INJECTED_DLL_NAME  = NULL;

static TCHAR* EXECUTABLE_NAME =  NULL;

#define TAGID_NULL          0

#define TAG_TYPE_LIST       0x7000
#define TAG_DATABASE        (0x1 | TAG_TYPE_LIST)
#define TAG_LIBRARY         (0x2 | TAG_TYPE_LIST)
#define TAG_INEXCLUDE       (0x3 | TAG_TYPE_LIST)
#define TAG_SHIM            (0x4 | TAG_TYPE_LIST)
#define TAG_EXE             (0x7 | TAG_TYPE_LIST)
#define TAG_MATCHING_FILE   (0x8 | TAG_TYPE_LIST)
#define TAG_SHIM_REF        (0x9 | TAG_TYPE_LIST)

#define TAG_TYPE_DWORD      0x4000
#define TAG_OS_PLATFORM     (0x23| TAG_TYPE_DWORD)

#define TAG_TYPE_STRINGREF  0x6000
#define TAG_NAME            (0x1 | TAG_TYPE_STRINGREF)
#define TAG_SHIM_TAGID      (0x4 | TAG_TYPE_DWORD)
#define TAG_MODULE          (0x3 | TAG_TYPE_STRINGREF)
#define TAG_APP_NAME        (0x6 | TAG_TYPE_STRINGREF)
#define TAG_DLLFILE         (0xA | TAG_TYPE_STRINGREF)

#define TAG_TYPE_BINARY     0x9000
#define TAG_EXE_ID          (0x4 | TAG_TYPE_BINARY)
#define TAG_DATABASE_ID     (0x7 | TAG_TYPE_BINARY)

#define TAG_TYPE_NULL       0x1000
#define TAG_INCLUDE         (0x1 | TAG_TYPE_NULL)

typedef enum _PATH_TYPE {
    DOS_PATH,
    NT_PATH
} PATH_TYPE;

typedef HANDLE PDB;
typedef DWORD TAG;
typedef DWORD INDEXID;
typedef DWORD TAGID;

typedef struct tagATTRINFO {
    TAG  tAttrID;
    DWORD dwFlags;
    union {
        ULONGLONG ullAttr;
        DWORD   dwAttr;
        TCHAR   *lpAttr;
    };
} ATTRINFO, *PATTRINFO;

typedef PDB (WINAPI *SdbCreateDatabasePtr)(LPCWSTR, PATH_TYPE);
typedef VOID (WINAPI *SdbCloseDatabaseWritePtr)(PDB);
typedef TAGID (WINAPI *SdbBeginWriteListTagPtr)(PDB, TAG);
typedef BOOL (WINAPI *SdbEndWriteListTagPtr)(PDB, TAGID);
typedef BOOL (WINAPI *SdbWriteStringTagPtr)(PDB, TAG, LPCWSTR);
typedef BOOL (WINAPI *SdbWriteDWORDTagPtr)(PDB, TAG, DWORD);
typedef BOOL (WINAPI *SdbWriteBinaryTagPtr)(PDB, TAG, PBYTE, DWORD);
typedef BOOL (WINAPI *SdbWriteNULLTagPtr)(PDB, TAG);

typedef struct _APPHELP_API {
    SdbCreateDatabasePtr         SdbCreateDatabase;
    SdbCloseDatabaseWritePtr     SdbCloseDatabaseWrite;
    SdbBeginWriteListTagPtr      SdbBeginWriteListTag;
    SdbEndWriteListTagPtr        SdbEndWriteListTag;
    SdbWriteStringTagPtr         SdbWriteStringTag;
    SdbWriteDWORDTagPtr          SdbWriteDWORDTag;
    SdbWriteBinaryTagPtr         SdbWriteBinaryTag;
    SdbWriteNULLTagPtr           SdbWriteNULLTag;
} APPHELP_API, *PAPPHELP_API;

BOOL static LoadAppHelpFunctions(HMODULE hAppHelp, PAPPHELP_API pAppHelp) {
    if (!(pAppHelp->SdbBeginWriteListTag = (SdbBeginWriteListTagPtr)GetProcAddress(hAppHelp, "SdbBeginWriteListTag"))) {
        fprintf(stderr, "[-] GetProcAddress(..., \"SdbBeginWriteListTag\")\n");
        return FALSE;
    }
    if (!(pAppHelp->SdbCloseDatabaseWrite = (SdbCloseDatabaseWritePtr)GetProcAddress(hAppHelp, "SdbCloseDatabaseWrite"))) {
        fprintf(stderr, "[-] GetProcAddress(..., \"SdbCloseDatabaseWrite\")\n");
        return FALSE;
    }
    if (!(pAppHelp->SdbCreateDatabase = (SdbCreateDatabasePtr)GetProcAddress(hAppHelp, "SdbCreateDatabase"))) {
        fprintf(stderr, "[-] GetProcAddress(..., \"SdbCreateDatabase\")\n");
        return FALSE;
    }
    if (!(pAppHelp->SdbEndWriteListTag = (SdbEndWriteListTagPtr)GetProcAddress(hAppHelp, "SdbEndWriteListTag"))) {
        fprintf(stderr, "[-] GetProcAddress(..., \"SdbEndWriteListTag\")\n");
        return FALSE;
    }
    if (!(pAppHelp->SdbWriteBinaryTag = (SdbWriteBinaryTagPtr)GetProcAddress(hAppHelp, "SdbWriteBinaryTag"))) {
        fprintf(stderr, "[-] GetProcAddress(..., \"SdbWriteBinaryTag\")\n");
        return FALSE;
    }
    if (!(pAppHelp->SdbWriteDWORDTag = (SdbWriteDWORDTagPtr)GetProcAddress(hAppHelp, "SdbWriteDWORDTag"))) {
        fprintf(stderr, "[-] GetProcAddress(..., \"SdbWriteDWORDTag\")\n");
        return FALSE;
    }
    if (!(pAppHelp->SdbWriteStringTag = (SdbWriteStringTagPtr)GetProcAddress(hAppHelp, "SdbWriteStringTag"))) {
        fprintf(stderr, "[-] GetProcAddress(..., \"SdbWriteStringTag\")\n");
        return FALSE;
    }
    if (!(pAppHelp->SdbWriteNULLTag = (SdbWriteNULLTagPtr)GetProcAddress(hAppHelp, "SdbWriteNULLTag"))) {
        fprintf(stderr, "[-] GetProcAddress(..., \"SdbWriteNULLTag\")\n");
        return FALSE;
    }
    return TRUE;
}

BOOL static DoStuff(PAPPHELP_API pAppHelp,int OS_PLATFORM)
{
    PDB db = NULL;
    TAGID tIdDatabase;
    TAGID tIdLibrary;
    TAGID tIdShim;
    TAGID tIdInexclude;
    TAGID tIdExe;
    TAGID tIdMatchingFile;
    TAGID tIdShimRef;
    GUID dbGUID, exeGUID;

	if ((CoCreateGuid(&dbGUID) != S_OK) ||
        (CoCreateGuid(&exeGUID) != S_OK)) return FALSE;

	if(OS_PLATFORM == 1)
	{
		db = pAppHelp->SdbCreateDatabase(L"MemShield32.sdb", DOS_PATH);
		INJECTED_DLL_NAME = L"MemShield32.dll";
	}
	if(OS_PLATFORM == 4)
	{
		db = pAppHelp->SdbCreateDatabase(L"MemShield64.sdb", DOS_PATH);
		INJECTED_DLL_NAME = L"MemShield64.dll";
	}
    if (db == NULL) {
        fprintf(stderr, "[-] SdbCreateDatabase failed : %lu\n", GetLastError());
        return FALSE;
    }
    tIdDatabase = pAppHelp->SdbBeginWriteListTag(db, TAG_DATABASE);
    pAppHelp->SdbWriteDWORDTag(db, TAG_OS_PLATFORM, OS_PLATFORM);
    pAppHelp->SdbWriteStringTag(db, TAG_NAME, L"MemShield_Database");
    pAppHelp->SdbWriteBinaryTag(db, TAG_DATABASE_ID, (PBYTE)&dbGUID, sizeof(GUID));
    tIdLibrary = pAppHelp->SdbBeginWriteListTag(db, TAG_LIBRARY);
    tIdShim = pAppHelp->SdbBeginWriteListTag(db, TAG_SHIM);
    pAppHelp->SdbWriteStringTag(db, TAG_NAME, L"MemShield_Shim");
    pAppHelp->SdbWriteStringTag(db, TAG_DLLFILE, INJECTED_DLL_NAME);
    tIdInexclude = pAppHelp->SdbBeginWriteListTag(db, TAG_INEXCLUDE);
    pAppHelp->SdbWriteNULLTag(db, TAG_INCLUDE);
    pAppHelp->SdbWriteStringTag(db, TAG_MODULE, L"*");
    pAppHelp->SdbEndWriteListTag(db, tIdInexclude);
    pAppHelp->SdbEndWriteListTag(db, tIdShim);
    pAppHelp->SdbEndWriteListTag(db, tIdLibrary);
    tIdExe = pAppHelp->SdbBeginWriteListTag(db, TAG_EXE);
    pAppHelp->SdbWriteStringTag(db, TAG_NAME, EXECUTABLE_NAME);
    pAppHelp->SdbWriteStringTag(db, TAG_APP_NAME, L"MemShield_Apps");
    pAppHelp->SdbWriteBinaryTag(db, TAG_EXE_ID,  (PBYTE)&exeGUID, sizeof(GUID));
	tIdMatchingFile = pAppHelp->SdbBeginWriteListTag(db, TAG_MATCHING_FILE);
    pAppHelp->SdbWriteStringTag(db, TAG_NAME, L"*");
    pAppHelp->SdbEndWriteListTag(db, tIdMatchingFile);
    tIdShimRef = pAppHelp->SdbBeginWriteListTag(db, TAG_SHIM_REF);
    pAppHelp->SdbWriteStringTag(db, TAG_NAME, L"MemShield_Shim");
	//pAppHelp->SdbWriteDWORDTag(db, TAG_SHIM_TAGID, 808);
    pAppHelp->SdbEndWriteListTag(db, tIdShimRef);
    pAppHelp->SdbEndWriteListTag(db, tIdExe);
    pAppHelp->SdbEndWriteListTag(db, tIdDatabase);
    pAppHelp->SdbCloseDatabaseWrite(db);
    return TRUE;
}

void Usage(TCHAR **argv)
{
	wprintf(L"Invalid arguments. Correct usage:\n%s <filename to protect>",argv[0]);
}

int _tmain(int argc, TCHAR *argv[]) {
    APPHELP_API api = {0};
    HMODULE hAppHelp = NULL;
    
	if(argc != 2) {Usage(argv); return 1;}
	else
		EXECUTABLE_NAME = argv[1];

    hAppHelp = LoadLibrary(TEXT("apphelp.dll"));
    if (hAppHelp == NULL) {
        fprintf(stderr, "[-] LoadLibrary failed %lu\n", GetLastError());
        return 1;
    }
    if (LoadAppHelpFunctions(hAppHelp, &api) == FALSE) {
        printf("[-] Failed to load apphelp api %lu!\n", GetLastError());
        return 1;
    }
    DoStuff(&api,1);
	DoStuff(&api,4);
    return 0;
}