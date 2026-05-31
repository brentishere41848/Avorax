#include "ZentorAvFilter.h"

static BOOLEAN
ZentorContainsInsensitive(_In_ PUNICODE_STRING Text, _In_ PCWSTR Needle)
{
    UNICODE_STRING needleString;

    if (Text == NULL || Text->Buffer == NULL) {
        return FALSE;
    }

    RtlInitUnicodeString(&needleString, Needle);
    return FsRtlIsNameInExpression(&needleString, Text, TRUE, NULL);
}

BOOLEAN
ZentorIsCriticalSystemPath(_In_ PUNICODE_STRING NormalizedName)
{
    return ZentorContainsInsensitive(NormalizedName, L"*\\Windows\\System32\\*") ||
           ZentorContainsInsensitive(NormalizedName, L"*\\Windows\\SysWOW64\\*") ||
           ZentorContainsInsensitive(NormalizedName, L"*\\Windows\\WinSxS\\*");
}

BOOLEAN
ZentorShouldExcludePath(_In_ PUNICODE_STRING NormalizedName)
{
    if (NormalizedName == NULL || NormalizedName->Buffer == NULL) {
        return TRUE;
    }

    if (ZentorIsCriticalSystemPath(NormalizedName)) {
        return TRUE;
    }

    return ZentorContainsInsensitive(NormalizedName, L"*\\Avorax\\Quarantine\\*") ||
           ZentorContainsInsensitive(NormalizedName, L"*\\zentor_local_core.exe") ||
           ZentorContainsInsensitive(NormalizedName, L"*\\zentor_guard_service.exe") ||
           ZentorContainsInsensitive(NormalizedName, L"*\\ZentorAvFilter.sys");
}
