#include "PasusAvFilter.h"

NTSTATUS
PasusBuildScanRequest(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PASUS_SCAN_EVENT_TYPE EventType,
    _Out_ PPASUS_SCAN_REQUEST Request
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    size_t copyChars;

    UNREFERENCED_PARAMETER(FltObjects);

    RtlZeroMemory(Request, sizeof(PASUS_SCAN_REQUEST));
    Request->Version = 1;
    Request->RequestId = (ULONG)InterlockedIncrement(&PasusGlobals.NextRequestId);
    Request->EventType = EventType;
    Request->ProcessId = HandleToULong(PsGetCurrentProcessId());
    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
        Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        Request->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    } else {
        Request->DesiredAccess = 0;
    }
    KeQuerySystemTimePrecise(&Request->TimestampUtc);

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return status;
    }

    copyChars = min((size_t)(nameInfo->Name.Length / sizeof(WCHAR)), PASUS_MAX_PATH_CHARS - 1);
    RtlCopyMemory(Request->FilePath, nameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
    Request->FilePath[copyChars] = L'\0';

    FltReleaseFileNameInformation(nameInfo);
    return STATUS_SUCCESS;
}
