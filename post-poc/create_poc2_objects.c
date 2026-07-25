/* Helper: create AND HOLD handles to Global\ objects for PoC 2 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

int main() {
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    HANDLE hEvent, hMutex, hSection, hPipe;
    int ok = 0;

    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    /* Keep stdout alive: unbuffered */
    setbuf(stdout, NULL);

    printf("OWNER_PID=%lu\n", GetCurrentProcessId());
    {
        DWORD sess;
        ProcessIdToSessionId(GetCurrentProcessId(), &sess);
        printf("OWNER_SESSION=%lu\n", sess);
    }

    /* Create Event */
    hEvent = CreateEventW(&sa, TRUE, FALSE, L"Global\\POC2_CrossSession_EvilEvent_20260725");
    if (hEvent) { printf("EVENT=OK\n"); ok++; } else printf("EVENT=FAIL(%lu)\n", GetLastError());

    /* Create Mutex */
    hMutex = CreateMutexW(&sa, FALSE, L"Global\\POC2_CrossSession_EvilMutex_20260725");
    if (hMutex) { printf("MUTEX=OK\n"); ok++; } else printf("MUTEX=FAIL(%lu)\n", GetLastError());

    /* Create Section and write marker */
    hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 4096,
                                  L"Global\\POC2_CrossSession_EvilSection_20260725");
    if (hSection) {
        printf("SECTION=OK\n");
        void *map = MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
        if (map) {
            memcpy(map, "MARKER_OWNER_SESSION_9\x00", 24);
            UnmapViewOfFile(map);
            printf("MARKER=OK\n");
        }
        ok++;
    } else printf("SECTION=FAIL(%lu)\n", GetLastError());

    /* Create Pipe server */
    hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\Global\\POC2_CrossSession_EvilPipe_20260725",
                             PIPE_ACCESS_DUPLEX,
                             PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                             1, 4096, 4096, 0, &sa);
    if (hPipe != INVALID_HANDLE_VALUE) { printf("PIPE=OK\n"); ok++; }
    else printf("PIPE=FAIL(%lu)\n", GetLastError());

    printf("OBJECTS=%d\n", ok);
    if (ok >= 3) {
        printf("READY\n");  /* Signal that objects are live */
        fflush(stdout);
        /* Hold handles until process is killed */
        while (1) Sleep(10000);
    }
    return 0;
}
