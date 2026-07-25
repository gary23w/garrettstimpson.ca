/*
 * PoC 3: Windows Global\ DACL Audit (robust enumeration)
 * 
 * Opens each named object in \BaseNamedObjects with its appropriate
 * Win32 API (OpenEventW/OpenMutexW/OpenSemaphoreW/OpenFileMappingW)
 * and queries its security descriptor to classify DACL strength.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <aclapi.h>
#include <sddl.h>

/* Missing NT defines */
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY      0x0001
#define DIRECTORY_TRAVERSE   0x0002
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

/* NT API declarations */
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS (NTAPI *pNtOpenDirectoryObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtQueryDirectoryObject)(
    HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

static pNtOpenDirectoryObject NtOpenDirectoryObject = NULL;
static pNtQueryDirectoryObject NtQueryDirectoryObject = NULL;

static int init_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    NtOpenDirectoryObject = (pNtOpenDirectoryObject)
        GetProcAddress(ntdll, "NtOpenDirectoryObject");
    NtQueryDirectoryObject = (pNtQueryDirectoryObject)
        GetProcAddress(ntdll, "NtQueryDirectoryObject");
    return (NtOpenDirectoryObject && NtQueryDirectoryObject) ? 1 : 0;
}

/* DACL classification result */
typedef enum {
    DACL_NULL     = 0,   /* NULL DACL — no security */
    DACL_EVERYONE = 1,   /* Everyone SID present */
    DACL_WEAK     = 2,   /* Authenticated Users / Users, no Admin-only */
    DACL_STRONG   = 3,   /* SYSTEM + Administrators only */
    DACL_DENIED   = 4,   /* Cannot read DACL */
    DACL_OTHER    = 5    /* Other unusual configuration */
} DaclClass;

static const char *dacl_label(DaclClass c) {
    switch(c) {
        case DACL_NULL:     return "NULL-DACL";
        case DACL_EVERYONE: return "EVERYONE";
        case DACL_WEAK:     return "WEAK";
        case DACL_STRONG:   return "STRONG";
        case DACL_DENIED:   return "DENIED";
        case DACL_OTHER:    return "OTHER";
        default:            return "???";
    }
}

static DaclClass classify_dacl(PACL dacl) {
    if (dacl == NULL) return DACL_NULL;

    ACL_SIZE_INFORMATION acl_info;
    acl_info.AceCount = 0;
    if (!GetAclInformation(dacl, &acl_info, sizeof(acl_info), AclSizeInformation))
        return DACL_DENIED;

    int has_everyone = 0, has_auth = 0, has_system = 0, has_admin = 0;

    for (DWORD i = 0; i < acl_info.AceCount; i++) {
        LPVOID ace = NULL;
        if (!GetAce(dacl, i, &ace)) continue;
        ACE_HEADER *hdr = (ACE_HEADER *)ace;
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;

        ACCESS_ALLOWED_ACE *aa = (ACCESS_ALLOWED_ACE *)ace;
        PSID sid = (PSID)&aa->SidStart;
        char *sid_str = NULL;
        ConvertSidToStringSidA(sid, &sid_str);

        if (IsWellKnownSid(sid, WinWorldSid))            has_everyone = 1;
        if (IsWellKnownSid(sid, WinAuthenticatedUserSid)) has_auth = 1;
        if (IsWellKnownSid(sid, WinLocalSystemSid))       has_system = 1;
        if (IsWellKnownSid(sid, WinBuiltinAdministratorsSid)) has_admin = 1;

        if (sid_str) LocalFree(sid_str);
    }

    if (has_everyone) return DACL_EVERYONE;
    if (has_system && has_admin) return DACL_STRONG;
    if (has_auth || has_admin) return DACL_WEAK;
    return DACL_OTHER;
}

static DaclClass check_object(const char *obj_name, const char *type,
                               const char *full_nt_path, int is_global) {
    (void)full_nt_path;
    char win32_path[1024];
    if (is_global) {
        snprintf(win32_path, sizeof(win32_path), "Global\\%s", obj_name);
    } else {
        snprintf(win32_path, sizeof(win32_path), "Local\\%s", obj_name);
    }
    WCHAR wpath[1024];
    MultiByteToWideChar(CP_ACP, 0, win32_path, -1, wpath, 1024);

    HANDLE hObj = NULL;

    if (strcmp(type, "Event") == 0) {
        hObj = OpenEventW(EVENT_ALL_ACCESS, FALSE, wpath);
    } else if (strcmp(type, "Mutant") == 0) {
        hObj = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, wpath);
    } else if (strcmp(type, "Semaphore") == 0) {
        hObj = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, wpath);
    } else if (strcmp(type, "Section") == 0) {
        hObj = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, wpath);
    } else if (strcmp(type, "Timer") == 0) {
        hObj = OpenWaitableTimerW(TIMER_ALL_ACCESS, FALSE, wpath);
    } else {
        return DACL_DENIED;
    }

    if (!hObj) return DACL_DENIED;

    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD ret = GetSecurityInfo(hObj, SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    CloseHandle(hObj);

    if (ret != ERROR_SUCCESS || !sd) {
        if (sd) LocalFree(sd);
        return DACL_DENIED;
    }

    DaclClass c = classify_dacl(dacl);
    LocalFree(sd);
    return c;
}

/* Enumerate a directory and audit each object */
static void enum_and_audit(const char *full_path, const char *display, int is_global) {
    HANDLE hDir = NULL;
    UNICODE_STRING objName;
    OBJECT_ATTRIBUTES oa;
    WCHAR wpath[1024];
    NTSTATUS status;
    ULONG context = 0, ret_len = 0;
    char buffer[65536];

    MultiByteToWideChar(CP_ACP, 0, full_path, -1, wpath, 1024);
    RtlInitUnicodeString(&objName, wpath);
    InitializeObjectAttributes(&oa, &objName, 0, NULL, NULL);

    status = NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (!NT_SUCCESS(status)) {
        printf("[SKIP] %s — cannot open directory (0x%08lx)\n", display, (long)status);
        return;
    }

    printf("\n=== Dir: %s ===\n", display);

    int counts[6] = {0};
    int total_open = 0;
    int max_objects = 500;  /* safety cap */

    /* Iterate in batches */
    while (1) {
        BOOLEAN restart = (context == 0) ? TRUE : FALSE;
        status = NtQueryDirectoryObject(hDir, buffer, sizeof(buffer),
                                        FALSE, restart, &ret_len, &context);
        if (!NT_SUCCESS(status)) break;
        if (ret_len == 0) break;

        OBJECT_DIRECTORY_INFORMATION *info = (OBJECT_DIRECTORY_INFORMATION *)buffer;
        for (ULONG i = 0; i < ret_len; i++) {
            char name[512], type[64];
            WideCharToMultiByte(CP_ACP, 0, info[i].Name.Buffer,
                info[i].Name.Length / sizeof(WCHAR), name, sizeof(name), NULL, NULL);
            WideCharToMultiByte(CP_ACP, 0, info[i].TypeName.Buffer,
                info[i].TypeName.Length / sizeof(WCHAR), type, sizeof(type), NULL, NULL);
            name[511] = 0; type[63] = 0;

            if (strcmp(type, "Directory") == 0) continue;

            char obj_full[1024];
            snprintf(obj_full, sizeof(obj_full), "%s\\%s", full_path, name);

            DaclClass c = check_object(name, type, obj_full, is_global);
            counts[c]++;
            total_open++;

            if (total_open >= max_objects) {
                printf("  ... capped at %d objects for stability ...\n", max_objects);
                goto done;
            }

            if (c == DACL_NULL || c == DACL_EVERYONE || c == DACL_WEAK) {
                printf("  [%s] %s (%s)\n", dacl_label(c), name, type);
            }

            if (total_open % 250 == 0) {
                printf("  ... %d objects processed ...\n", total_open);
            }
        }
    }

done:
    CloseHandle(hDir);

    printf("\n--- %s Summary ---\n", display);
    printf("  Total attempted: %d\n", total_open);
    printf("  NULL-DACL:       %d\n", counts[DACL_NULL]);
    printf("  EVERYONE:        %d\n", counts[DACL_EVERYONE]);
    printf("  WEAK:            %d\n", counts[DACL_WEAK]);
    printf("  STRONG:          %d\n", counts[DACL_STRONG]);
    printf("  DENIED:          %d\n", counts[DACL_DENIED]);
    printf("  OTHER:           %d\n", counts[DACL_OTHER]);
}

int main(void) {
    DWORD pid = GetCurrentProcessId();
    DWORD session = 0;
    if (!ProcessIdToSessionId(pid, &session)) session = 0;

    printf("=== PoC 3: Windows Global\\ DACL Audit ===\n");
    printf("PID: %lu  Session: %lu\n\n", pid, session);

    if (!init_ntdll()) {
        printf("[!] Failed to load NT API\n");
        return 1;
    }

    char sess_path[256];
    snprintf(sess_path, sizeof(sess_path), "\\Sessions\\%lu\\BaseNamedObjects", session);

    enum_and_audit("\\BaseNamedObjects", "\\BaseNamedObjects", 1);
    enum_and_audit(sess_path, sess_path, 0);

    printf("\n=== Impact ===\n");
    printf("Objects classified NULL-DACL or EVERYONE can be opened\n");
    printf("and manipulated by ANY process on the system, regardless\n");
    printf("of session — cross-session interference is possible.\n");
    printf("WEAK objects can be manipulated by any authenticated user.\n");
    return 0;
}
