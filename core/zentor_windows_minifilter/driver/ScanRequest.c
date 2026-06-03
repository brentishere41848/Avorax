#include "ZentorAvFilter.h"

static VOID
ZentorTryCaptureFileMetadata(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PZENTOR_SCAN_REQUEST Request
    )
{
    FILE_STANDARD_INFORMATION standardInfo;
    FILE_BASIC_INFORMATION basicInfo;
    NTSTATUS status;
    ULONG bytesReturned = 0;

    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        return;
    }

    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &standardInfo,
        sizeof(standardInfo),
        FileStandardInformation,
        &bytesReturned);
    if (NT_SUCCESS(status)) {
        Request->FileSize = standardInfo.EndOfFile;
    }

    bytesReturned = 0;
    status = FltQueryInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &basicInfo,
        sizeof(basicInfo),
        FileBasicInformation,
        &bytesReturned);
    if (NT_SUCCESS(status)) {
        Request->FileAttributes = basicInfo.FileAttributes;
    }
}

static VOID
ZentorTryCaptureRenameTarget(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Out_ PZENTOR_SCAN_REQUEST Request
    )
{
    PFILE_RENAME_INFORMATION renameInfo;
    ULONG copyChars;

    if (Data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION ||
        Data->Iopb->Parameters.SetFileInformation.InfoBuffer == NULL) {
        return;
    }

    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileRenameInformation &&
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass != FileRenameInformationEx) {
        return;
    }

    renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    copyChars = min(renameInfo->FileNameLength / sizeof(WCHAR), ZENTOR_MAX_RENAME_TARGET_CHARS - 1);
    if (copyChars == 0) {
        return;
    }

    RtlCopyMemory(Request->RenameTarget, renameInfo->FileName, copyChars * sizeof(WCHAR));
    Request->RenameTarget[copyChars] = L'\0';
}

NTSTATUS
ZentorBuildScanRequest(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ZENTOR_SCAN_EVENT_TYPE EventType,
    _Out_ PZENTOR_SCAN_REQUEST Request
    )
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    size_t copyChars;

    RtlZeroMemory(Request, sizeof(ZENTOR_SCAN_REQUEST));
    Request->Version = 2;
    Request->RequestId = (ULONG)InterlockedIncrement(&ZentorGlobals.NextRequestId);
    Request->EventType = EventType;
    Request->ProcessId = HandleToULong(PsGetCurrentProcessId());
    Request->FileSize.QuadPart = -1;

    if (Data->Iopb->MajorFunction == IRP_MJ_CREATE &&
        Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        Request->DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
        Request->CreateDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
        Request->FileAttributes = Data->Iopb->Parameters.Create.FileAttributes;
    } else {
        Request->DesiredAccess = 0;
        Request->CreateDisposition = 0;
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

    copyChars = min((size_t)(nameInfo->Name.Length / sizeof(WCHAR)), ZENTOR_MAX_PATH_CHARS - 1);
    RtlCopyMemory(Request->FilePath, nameInfo->Name.Buffer, copyChars * sizeof(WCHAR));
    Request->FilePath[copyChars] = L'\0';

    FltReleaseFileNameInformation(nameInfo);
    ZentorTryCaptureFileMetadata(FltObjects, Request);
    ZentorTryCaptureRenameTarget(Data, Request);
    return STATUS_SUCCESS;
}
