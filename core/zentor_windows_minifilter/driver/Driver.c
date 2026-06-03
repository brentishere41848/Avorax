#include "ZentorAvFilter.h"

ZENTOR_FILTER_GLOBALS ZentorGlobals;

CONST FLT_OPERATION_REGISTRATION ZentorCallbacks[] = {
    {
        IRP_MJ_CREATE,
        0,
        ZentorPreCreate,
        NULL
    },
    {
        IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
        0,
        ZentorPreAcquireForSectionSync,
        NULL
    },
    {
        IRP_MJ_WRITE,
        0,
        ZentorPreWrite,
        NULL
    },
    {
        IRP_MJ_SET_INFORMATION,
        0,
        ZentorPreSetInformation,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION ZentorFilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    ZentorCallbacks,
    ZentorUnload,
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

    RtlZeroMemory(&ZentorGlobals, sizeof(ZentorGlobals));
    ZentorGlobals.Mode = ZentorModeBlockConfirmedThreats;
    ZentorGlobals.PreExecutionTimeoutMs = ZENTOR_DEFAULT_TIMEOUT_MS;

    status = FltRegisterFilter(DriverObject, &ZentorFilterRegistration, &ZentorGlobals.Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZentorCreateCommunicationPort(DriverObject);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(ZentorGlobals.Filter);
        ZentorGlobals.Filter = NULL;
        return status;
    }

    status = FltStartFiltering(ZentorGlobals.Filter);
    if (!NT_SUCCESS(status)) {
        ZentorCloseCommunicationPort();
        FltUnregisterFilter(ZentorGlobals.Filter);
        ZentorGlobals.Filter = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
ZentorUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    ZentorCloseCommunicationPort();
    if (ZentorGlobals.Filter != NULL) {
        FltUnregisterFilter(ZentorGlobals.Filter);
        ZentorGlobals.Filter = NULL;
    }
    return STATUS_SUCCESS;
}
