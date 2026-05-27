#include "PasusAvFilter.h"

FLT_PREOP_CALLBACK_STATUS
PasusPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PASUS_SCAN_REQUEST request;
    PASUS_SCAN_VERDICT verdict;
    UNICODE_STRING requestName;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (PasusGlobals.Mode == PasusModeDisabled || PasusGlobals.Mode == PasusModeObserveOnly) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = PasusBuildScanRequest(Data, FltObjects, PasusEventFileOpen, &request);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    RtlInitUnicodeString(&requestName, request.FilePath);
    if (PasusShouldExcludePath(&requestName)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = PasusSendScanRequest(&request, &verdict);
    if (!NT_SUCCESS(status) && status != STATUS_TIMEOUT) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (PasusShouldBlockVerdict(&verdict)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
PasusPreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    PASUS_SCAN_REQUEST request;
    PASUS_SCAN_VERDICT verdict;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (PasusGlobals.Mode == PasusModeDisabled || PasusGlobals.Mode == PasusModeObserveOnly) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = PasusBuildScanRequest(Data, FltObjects, PasusEventSectionCreateAttempt, &request);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = PasusSendScanRequest(&request, &verdict);
    if (!NT_SUCCESS(status) && status != STATUS_TIMEOUT) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (PasusShouldBlockVerdict(&verdict)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
