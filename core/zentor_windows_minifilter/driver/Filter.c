#include "ZentorAvFilter.h"

static ZENTOR_SCAN_EVENT_TYPE
ZentorClassifyCreateEvent(_In_ PFLT_CALLBACK_DATA Data)
{
    ACCESS_MASK desiredAccess = 0;
    ULONG createDisposition = 0;

    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }

    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff;
    if ((desiredAccess & FILE_EXECUTE) != 0) {
        return ZentorEventImageExecuteAttempt;
    }

    if (createDisposition == FILE_CREATE ||
        createDisposition == FILE_OPEN_IF ||
        createDisposition == FILE_OVERWRITE_IF ||
        createDisposition == FILE_SUPERSEDE) {
        return ZentorEventFileCreate;
    }

    return ZentorEventFileOpen;
}

static BOOLEAN
ZentorIsRenameInformationClass(_In_ FILE_INFORMATION_CLASS FileInformationClass)
{
    return FileInformationClass == FileRenameInformation ||
           FileInformationClass == FileRenameInformationEx;
}

static FLT_PREOP_CALLBACK_STATUS
ZentorEvaluateRequest(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ZENTOR_SCAN_EVENT_TYPE EventType
    )
{
    ZENTOR_SCAN_REQUEST request;
    ZENTOR_SCAN_VERDICT verdict;
    UNICODE_STRING requestName;
    NTSTATUS status;

    if (ZentorGlobals.Mode == ZentorModeDisabled || ZentorGlobals.Mode == ZentorModeObserveOnly) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = ZentorBuildScanRequest(Data, FltObjects, EventType, &request);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlInitUnicodeString(&requestName, request.FilePath);
    if (ZentorShouldExcludePath(&requestName)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = ZentorSendScanRequest(&request, &verdict);
    if (!NT_SUCCESS(status) && status != STATUS_TIMEOUT) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (ZentorShouldBlockVerdict(&verdict)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ZentorPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(CompletionContext);
    return ZentorEvaluateRequest(Data, FltObjects, ZentorClassifyCreateEvent(Data));
}

FLT_PREOP_CALLBACK_STATUS
ZentorPreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return ZentorEvaluateRequest(Data, FltObjects, ZentorEventSectionCreateAttempt);
}

FLT_PREOP_CALLBACK_STATUS
ZentorPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(CompletionContext);
    return ZentorEvaluateRequest(Data, FltObjects, ZentorEventFileWrite);
}

FLT_PREOP_CALLBACK_STATUS
ZentorPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!ZentorIsRenameInformationClass(Data->Iopb->Parameters.SetFileInformation.FileInformationClass)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return ZentorEvaluateRequest(Data, FltObjects, ZentorEventFileRename);
}
