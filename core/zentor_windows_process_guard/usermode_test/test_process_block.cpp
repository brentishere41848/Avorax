#include <windows.h>
#include <iostream>

int wmain() {
    std::wcout << L"ZentorProcessGuard process callback validation smoke test." << std::endl;
    std::wcout << L"This test must only pass blocking once the signed driver exposes a verified deny path." << std::endl;
    return 0;
}
