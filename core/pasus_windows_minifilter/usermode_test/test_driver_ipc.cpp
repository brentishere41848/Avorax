#include <windows.h>
#include <fltuser.h>
#include <iostream>

#pragma comment(lib, "FltLib.lib")

int wmain() {
    HANDLE port = INVALID_HANDLE_VALUE;
    HRESULT hr = FilterConnectCommunicationPort(
        L"\\PasusAvFilterPort",
        0,
        nullptr,
        0,
        nullptr,
        &port);

    if (FAILED(hr)) {
        std::wcerr << L"Failed to connect to PasusAvFilterPort: 0x"
                   << std::hex << hr << std::endl;
        return 1;
    }

    std::wcout << L"Connected to PasusAvFilterPort." << std::endl;
    CloseHandle(port);
    return 0;
}
