#include <windows.h>
#include <iostream>

// This test expects the Guard Service known-bad cache to contain the SHA-256
// of the harmless fixture path passed as argv[1]. It verifies that the driver
// denies opening the file when blockConfirmedThreats policy is active.

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        std::wcerr << L"usage: test_known_bad_block.exe <fixture-path>" << std::endl;
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
        std::wcout << L"Known-bad fixture was blocked before open." << std::endl;
        return 0;
    }

    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }

    std::wcerr << L"Known-bad fixture was not blocked. GetLastError="
               << GetLastError() << std::endl;
    return 1;
}
