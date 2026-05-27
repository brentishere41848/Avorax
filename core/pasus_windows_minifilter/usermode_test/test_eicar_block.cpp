#include <windows.h>
#include <iostream>

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::wcerr << L"usage: test_eicar_block.exe <safe-eicar-path>" << std::endl;
        return 2;
    }

    HANDLE file = CreateFileW(
        argv[1],
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED) {
        std::wcout << L"EICAR test file was blocked before open." << std::endl;
        return 0;
    }

    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }

    std::wcerr << L"EICAR test file was not blocked. GetLastError="
               << GetLastError() << std::endl;
    return 1;
}
