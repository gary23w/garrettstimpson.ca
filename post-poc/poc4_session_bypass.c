/*
 * PoC 4 — Windows Session Boundary Bypass (NT API native path)
 * 
 * Opens \Sessions\X\BaseNamedObjects directly via NT namespace,
 * bypassing the Win32 Global\ / Local\ prefix routing entirely.
 * Each discovered object is opened by type and its DACL classified:
 *   NULL_DACL | EVERYONE_ALL_ACCESS | WEAK_ACL | CLASSIFIED | DENIED
 *
 * Build:  x86_64-w64-mingw32-gcc -O2 poc4_session_bypass.c \
 *         -o poc4.exe -ladvapi32 -lwtsapi32 -lntdll
 * Run:    poc4.exe   (as Administrator recommended)
 *
 * Author: Garrett Stimpson — 2026-07-25
 * License: BSD-3-Clause (educational / blue-team only)
 */

#include <windows.h>
#include <winternl.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "ntdll.lib")

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
/* ── NT API forward declarations ─────────────────────────────────── */

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS (NTAPI *pNtOpenDirectoryObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtQueryDirectoryObject)(
    HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

typedef NTSTATUS (NTAPI *pNtQuerySecurityObject)(
    HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG);

typedef NTSTATUS (NTAPI *pNtOpenEvent)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtOpenMutant)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtOpenSemaphore)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtOpenSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtOpenTimer)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtOpenJobObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtOpenSymbolicLinkObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef NTSTATUS (NTAPI *pNtOpenKeyedEvent)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

typedef VOID (NTAPI *pRtlInitUnicodeString)(
    PUNICODE_STRING, PCWSTR);

typedef VOID (NTAPI *pRtlFreeUnicodeString)(PUNICODE_STRING);

/* ── globals ─────────────────────────────────────────────────────── */

static pNtOpenDirectoryObject    _NtOpenDirectoryObject    = NULL;
static pNtQueryDirectoryObject   _NtQueryDirectoryObject   = NULL;
static pNtQuerySecurityObject    _NtQuerySecurityObject    = NULL;
static pNtOpenEvent              _NtOpenEvent              = NULL;
static pNtOpenMutant             _NtOpenMutant             = NULL;
static pNtOpenSemaphore          _NtOpenSemaphore          = NULL;
static pNtOpenSection            _NtOpenSection            = NULL;
static pNtOpenTimer              _NtOpenTimer              = NULL;
static pNtOpenJobObject          _NtOpenJobObject          = NULL;
static pNtOpenSymbolicLinkObject _NtOpenSymbolicLinkObject = NULL;
static pNtOpenKeyedEvent         _NtOpenKeyedEvent         = NULL;
static pRtlInitUnicodeString     _RtlInitUnicodeString     = NULL;
static pRtlFreeUnicodeString     _RtlFreeUnicodeString     = NULL;

typedef enum {
    DACL_NULL_DACL = 0,
    DACL_EVERYONE_ALL_ACCESS,
    DACL_WEAK_ACL,
    DACL_CLASSIFIED,
    DACL_DENIED,
    DACL_OTHER
} dacl_class_t;

static const char *dacl_names[] = {
    "NULL_DACL",
    "EVERYONE_ALL_ACCESS",
    "WEAK_ACL",
    "CLASSIFIED",
    "DENIED",
    "OTHER"
};

typedef struct {
    dacl_class_t class;
    uint32_t     count;
} audit_summary_t;

static audit_summary_t summary[6];

/* trace logger */
static FILE *trc = NULL;

/* ── helpers ─────────────────────────────────────────────────────── */

static int load_nt(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
#define L(fn) do { \
        if (trc) { fprintf(trc, "TRACE: load_nt — resolving " #fn "\n"); fflush(trc); } \
        _##fn = (p##fn)GetProcAddress(ntdll, #fn); \
        if (!_##fn) { if (trc) { fprintf(trc, "TRACE: load_nt — FAILED " #fn "\n"); fflush(trc); } return 0; } \
    } while(0)
    L(NtOpenDirectoryObject);
    L(NtQueryDirectoryObject);
    L(NtQuerySecurityObject);
    L(NtOpenEvent);
    L(NtOpenMutant);
    L(NtOpenSemaphore);
    L(NtOpenSection);
    L(NtOpenTimer);
    L(NtOpenJobObject);
    L(NtOpenSymbolicLinkObject);
    L(NtOpenKeyedEvent);
    L(RtlInitUnicodeString);
    L(RtlFreeUnicodeString);
#undef L
    return 1;
}

static dacl_class_t classify_dacl(PSECURITY_DESCRIPTOR psd) {
    if (!psd) return DACL_NULL_DACL;
    BOOL dacl_present = FALSE, dacl_defaulted = FALSE;
    PACL pacl = NULL;
    if (!GetSecurityDescriptorDacl(psd, &dacl_present, &pacl, &dacl_defaulted))
        return DACL_OTHER;
    if (!dacl_present || !pacl) return DACL_NULL_DACL;
    ACL_SIZE_INFORMATION asi = {0};
    if (!GetAclInformation(pacl, &asi, sizeof(asi), AclSizeInformation))
        return DACL_OTHER;
    if (asi.AceCount == 0) return DACL_NULL_DACL;
    SID_IDENTIFIER_AUTHORITY world_auth = SECURITY_WORLD_SID_AUTHORITY;
    PSID everyone_sid = NULL;
    if (!AllocateAndInitializeSid(&world_auth, 1, SECURITY_WORLD_RID,
                                   0,0,0,0,0,0,0, &everyone_sid))
        return DACL_OTHER;
    int found_everyone = 0;
    int found_write    = 0;
    int found_all      = 0;
    for (DWORD i = 0; i < asi.AceCount; i++) {
        LPVOID ace = NULL;
        if (!GetAce(pacl, i, &ace)) continue;
        BYTE ace_type = ((ACE_HEADER*)ace)->AceType;
        ACCESS_MASK mask = 0;
        PSID ace_sid = NULL;
        if (ace_type == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *aa = (ACCESS_ALLOWED_ACE*)ace;
            mask = aa->Mask;
            ace_sid = (PSID)&aa->SidStart;
        } else if (ace_type == ACCESS_ALLOWED_OBJECT_ACE_TYPE) {
            ACCESS_ALLOWED_OBJECT_ACE *ao = (ACCESS_ALLOWED_OBJECT_ACE*)ace;
            mask = ao->Mask;
            ace_sid = (PSID)&ao->SidStart;
        } else {
            continue;
        }
        if (EqualSid(ace_sid, everyone_sid)) {
            found_everyone = 1;
            if ((mask & GENERIC_ALL) == GENERIC_ALL) found_all = 1;
            if (mask & (GENERIC_WRITE | WRITE_DAC | WRITE_OWNER)) found_write = 1;
        }
    }
    FreeSid(everyone_sid);
    if (found_everyone && found_all) return DACL_EVERYONE_ALL_ACCESS;
    if (found_everyone && found_write) return DACL_WEAK_ACL;
    if (found_everyone) return DACL_CLASSIFIED;
    return DACL_CLASSIFIED;
}

/* Build an NT object name string, e.g. \Sessions\9\BaseNamedObjects\Foo */
static void make_obj_name(wchar_t *buf, size_t buf_cch,
                          const wchar_t *dir, const wchar_t *name) {
    if (dir && dir[0])
        _snwprintf(buf, buf_cch, L"%s\\%s", dir, name);
    else
        wcsncpy(buf, name, buf_cch);
    buf[buf_cch-1] = 0;
}

/* Attempt to open a named object by its type, using NT API */
static dacl_class_t open_and_classify(const wchar_t *full_path,
                                      const wchar_t *type_name) {
    UNICODE_STRING us;
    _RtlInitUnicodeString(&us, full_path);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE handle = NULL;
    ACCESS_MASK desired = READ_CONTROL;
    NTSTATUS st = 0;

    if (!type_name) goto done;
    if (_wcsicmp(type_name, L"Event") == 0)
        st = _NtOpenEvent(&handle, desired, &oa);
    else if (_wcsicmp(type_name, L"Mutant") == 0)
        st = _NtOpenMutant(&handle, desired, &oa);
    else if (_wcsicmp(type_name, L"Semaphore") == 0)
        st = _NtOpenSemaphore(&handle, desired, &oa);
    else if (_wcsicmp(type_name, L"Section") == 0)
        st = _NtOpenSection(&handle, desired, &oa);
    else if (_wcsicmp(type_name, L"Timer") == 0)
        st = _NtOpenTimer(&handle, desired, &oa);
    else if (_wcsicmp(type_name, L"Job") == 0)
        st = _NtOpenJobObject(&handle, desired, &oa);
    else if (_wcsicmp(type_name, L"SymbolicLink") == 0)
        st = _NtOpenSymbolicLinkObject(&handle, desired, &oa);
    else if (_wcsicmp(type_name, L"KeyedEvent") == 0)
        st = _NtOpenKeyedEvent(&handle, desired, &oa);
    else
        goto done;

    if (st != 0 || !handle) goto done;

    /* Query security descriptor */
    BYTE sd_buf[4096];
    ULONG needed = 0;
    st = _NtQuerySecurityObject(handle,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
            DACL_SECURITY_INFORMATION, sd_buf, sizeof(sd_buf), &needed);
    CloseHandle(handle);
    if (st == 0)
        return classify_dacl((PSECURITY_DESCRIPTOR)sd_buf);
    return DACL_DENIED;

done:
    if (handle) CloseHandle(handle);
    return DACL_DENIED;
}

/* ── directory enumeration ───────────────────────────────────────── */

#define MAX_OBJS 2000
#define BUF_SIZE  0x20000

static int audit_directory(const wchar_t *dir_path, const char *label,
                           FILE *out) {
    if (trc) { fprintf(trc, "TRACE: audit_directory ENTER '%s'\n", label); fflush(trc); }
    UNICODE_STRING us;
    _RtlInitUnicodeString(&us, dir_path);
    if (trc) { fprintf(trc, "TRACE: RtlInitUnicodeString done\n"); fflush(trc); }
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hdir = NULL;
    NTSTATUS st = _NtOpenDirectoryObject(&hdir, DIRECTORY_QUERY, &oa);
    if (trc) { fprintf(trc, "TRACE: about to NtOpenDirectoryObject\n"); fflush(trc); }
    if (trc) { fprintf(trc, "TRACE: NtOpenDirectoryObject returned 0x%08lx\n", (unsigned long)st); fflush(trc); }
    if (st != 0) {
        fprintf(out, "[!] Cannot open directory %S (0x%08lx)\n",
                dir_path, st);
        return 0;
    }

    POBJECT_DIRECTORY_INFORMATION buf =
        (POBJECT_DIRECTORY_INFORMATION)malloc(BUF_SIZE);
    if (trc) { fprintf(trc, "TRACE: malloc for dir buf (size %u) ok\n", (unsigned)BUF_SIZE); fflush(trc); }
    if (!buf) { CloseHandle(hdir); return 0; }

    fprintf(out, "══════════════════════════════════════════════════\n");
    fprintf(out, "%s  (%S)\n\n", label, dir_path);

    ULONG idx = 0, total = 0, ctx = 0;
    int first = 1;
    while (1) {
        if (trc) { fprintf(trc, "TRACE: about to call NtQueryDirectoryObject (first=%d, ctx=%lu)\n", first, (unsigned long)ctx); fflush(trc); }
        ULONG returned = 0;
        st = _NtQueryDirectoryObject(hdir, buf, BUF_SIZE, TRUE,
                                      first, &ctx, &returned);
        if (trc) { fprintf(trc, "TRACE: NtQueryDirectoryObject -> 0x%08lx ret=%lu\n", (unsigned long)st, (unsigned long)returned); fflush(trc); }
        first = 0;
        if (st != 0 || returned == 0) break;

        /* ReturnSingleEntry=TRUE: exactly one entry at buf[0] */
        POBJECT_DIRECTORY_INFORMATION entry = (POBJECT_DIRECTORY_INFORMATION)buf;
        wchar_t name_buf[512] = {0};
        wchar_t type_buf[256] = {0};
        if (entry->Name.Buffer && entry->Name.Length > 0)
            wcsncpy(name_buf, entry->Name.Buffer,
                    min(entry->Name.Length / sizeof(wchar_t), 510));
        if (entry->TypeName.Buffer && entry->TypeName.Length > 0)
            wcsncpy(type_buf, entry->TypeName.Buffer,
                    min(entry->TypeName.Length / sizeof(wchar_t), 254));

        wchar_t full_path[1024];
        make_obj_name(full_path, 1024, dir_path, name_buf);

        if (trc) { fprintf(trc, "TRACE: before open_and_classify(%S, %S)\n", name_buf, type_buf); fflush(trc); }
        dacl_class_t cls = open_and_classify(full_path, type_buf);
        if (trc) { fprintf(trc, "TRACE: after open_and_classify -> %s\n", dacl_names[cls]); fflush(trc); }
        summary[cls].count++;

        if (cls == DACL_NULL_DACL || cls == DACL_EVERYONE_ALL_ACCESS ||
            cls == DACL_WEAK_ACL) {
            fprintf(out, "[%-24s] %-30S  (type: %S)\n",
                    dacl_names[cls], name_buf, type_buf);
        }

        total++;
        if (total >= MAX_OBJS) goto done;
        if (trc && total % 100 == 0) { fprintf(trc, "TRACE: item %lu processed\n", (unsigned long)total); fflush(trc); }
    }

done:
    fprintf(out, "\n  → enumerated %lu objects (cap %d)\n", total, MAX_OBJS);
    CloseHandle(hdir);
    free(buf);
    return 1;
}

/* ── main ────────────────────────────────────────────────────────── */

int main(void) {
    trc = fopen("poc4_trace.txt", "w");
    if (trc) { fprintf(trc, "TRACE: main entered\n"); fflush(trc); }
    if (!load_nt()) {
    if (trc) { fprintf(trc, "TRACE: load_nt returned 0 — FATAL\n"); fflush(trc); }
        fprintf(stderr, "FATAL: cannot load NT API\n");
        return 1;
    }
    memset(summary, 0, sizeof(summary));
    if (trc) { fprintf(trc, "TRACE: load_nt succeeded, summary zeroed\n"); fflush(trc); }

    FILE *out = fopen("poc4_dacl_audit.txt", "w");
    if (trc) { fprintf(trc, "TRACE: opening output file\n"); fflush(trc); }
    if (!out) out = stdout;

    fprintf(out, "PoC 4 — NT-Namespace Cross-Session DACL Audit\n");
    fprintf(out, "Garrett Stimpson, 2026-07-25\n");
    fprintf(out, "Opens objects via NT API directly (bypasses Win32 prefix layer)\n\n");

    /* 1. Current session BaseNamedObjects */
    DWORD my_sid = WTSGetActiveConsoleSessionId();
    if (trc) { fprintf(trc, "TRACE: my session = %lu\n", (unsigned long)my_sid); fflush(trc); }
    wchar_t dir1[256];
    _snwprintf(dir1, 256, L"\\Sessions\\%lu\\BaseNamedObjects", my_sid);
    if (trc) { fprintf(trc, "TRACE: dir1 built, calling audit_directory on current session\n"); fflush(trc); }
    audit_directory(dir1, "CURRENT SESSION BaseNamedObjects", out);
    if (trc) { fprintf(trc, "TRACE: current session audit returned\n"); fflush(trc); }

    /* 2. All possible sessions 0-9 */
    if (trc) { fprintf(trc, "TRACE: starting cross-session loop\n"); fflush(trc); }
    for (DWORD s = 0; s <= 9; s++) {
    if (trc) { fprintf(trc, "TRACE: entering cross-session loop\n"); fflush(trc); }
        if (s == my_sid) continue;
        wchar_t dirx[256];
        _snwprintf(dirx, 256, L"\\Sessions\\%lu\\BaseNamedObjects", s);
        char label[128];
        sprintf(label, "SESSION %lu BaseNamedObjects", s);
        audit_directory(dirx, label, out);
    }

    /* 3. Global namespace */
    if (trc) { fprintf(trc, "TRACE: about to audit Global namespace\n"); fflush(trc); }
    audit_directory(L"\\BaseNamedObjects", "GLOBAL \\BaseNamedObjects", out);

    /* Summary */
    if (trc) { fprintf(trc, "TRACE: printing summary\n"); fflush(trc); }
    fprintf(out, "\n──────────────────────────────────────────────────\n");
    fprintf(out, "AUDIT SUMMARY\n\n");
    for (int i = 0; i < 6; i++) {
        fprintf(out, "  %-24s : %u\n", dacl_names[i], summary[i].count);
    }

    if (out != stdout) { fclose(out); printf("Output written to poc4_dacl_audit.txt\n"); }
    if (trc) { fprintf(trc, "TRACE: done, exiting\n"); fflush(trc); }
    if (trc) fclose(trc);
    return 0;
}
