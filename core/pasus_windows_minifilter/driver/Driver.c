#include "PasusAvFilter.h"

PASUS_FILTER_GLOBALS PasusGlobals;

CONST FLT_OPERATION_REGISTRATION PasusCallbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        PasusPreCreate,
        NULL
    },
    {
        IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
        0,
        PasusPreAcquireForSectionSync,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION PasusFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    PasusCallbacks,
    PasusUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlZeroMemory(&PasusGlobals, sizeof(PasusGlobals));
    PasusGlobals.Mode = PasusModeBlockConfirmedThreats;
    PasusGlobals.PreExecutionTimeoutMs = PASUS_DEFAULT_TIMEOUT_MS;

    status = FltRegisterFilter(DriverObject, &PasusFilterRegistration, &PasusGlobals.Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PasusCreateCommunicationPort(DriverObject);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(PasusGlobals.Filter);
        PasusGlobals.Filter = NULL;
        return status;
    }

    status = FltStartFiltering(PasusGlobals.Filter);
    if (!NT_SUCCESS(status)) {
        PasusCloseCommunicationPort();
        FltUnregisterFilter(PasusGlobals.Filter);
        PasusGlobals.Filter = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
PasusUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    PasusCloseCommunicationPort();
    if (PasusGlobals.Filter != NULL) {
        FltUnregisterFilter(PasusGlobals.Filter);
        PasusGlobals.Filter = NULL;
    }
    return STATUS_SUCCESS;
}
