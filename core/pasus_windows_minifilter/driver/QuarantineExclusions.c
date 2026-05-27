#include "PasusAvFilter.h"

static BOOLEAN
PasusContainsInsensitive(_In_ PUNICODE_STRING Text, _In_ PCWSTR Needle)
{
    UNICODE_STRING needleString;

    if (Text == NULL || Text->Buffer == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&needleString, Needle);
    return FsRtlIsNameInExpression(&needleString, Text, TRUE, NULL);
}

BOOLEAN
PasusIsCriticalSystemPath(_In_ PUNICODE_STRING NormalizedName)
{
    return PasusContainsInsensitive(NormalizedName, L"*\\Windows\\System32\\*") ||
           PasusContainsInsensitive(NormalizedName, L"*\\Windows\\SysWOW64\\*") ||
           PasusContainsInsensitive(NormalizedName, L"*\\Windows\\WinSxS\\*");
}

BOOLEAN
PasusShouldExcludePath(_In_ PUNICODE_STRING NormalizedName)
{
    if (NormalizedName == NULL || NormalizedName->Buffer == NULL) {
        return TRUE;
    }

    if (PasusIsCriticalSystemPath(NormalizedName)) {
        return TRUE;
    }

    return PasusContainsInsensitive(NormalizedName, L"*\\Pasus\\Quarantine\\*") ||
           PasusContainsInsensitive(NormalizedName, L"*\\pasus_local_core.exe") ||
           PasusContainsInsensitive(NormalizedName, L"*\\pasus_guard_service.exe") ||
           PasusContainsInsensitive(NormalizedName, L"*\\PasusAvFilter.sys");
}
