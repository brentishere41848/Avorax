#include "PasusAvFilter.h"

static NTSTATUS
PasusPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie
    )
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    PasusGlobals.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

static VOID
PasusPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (PasusGlobals.ClientPort != NULL) {
        FltCloseClientPort(PasusGlobals.Filter, &PasusGlobals.ClientPort);
        PasusGlobals.ClientPort = NULL;
    }
}

static NTSTATUS
PasusPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
    )
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
}

NTSTATUS
PasusCreateCommunicationPort(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES objectAttributes;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;

    UNREFERENCED_PARAMETER(DriverObject);

    RtlInitUnicodeString(&portName, PASUS_FILTER_PORT_NAME);

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor);

    status = FltCreateCommunicationPort(
        PasusGlobals.Filter,
        &PasusGlobals.ServerPort,
        &objectAttributes,
        NULL,
        PasusPortConnect,
        PasusPortDisconnect,
        PasusPortMessage,
        1);

    FltFreeSecurityDescriptor(securityDescriptor);
    return status;
}

VOID
PasusCloseCommunicationPort(VOID)
{
    if (PasusGlobals.ClientPort != NULL) {
        FltCloseClientPort(PasusGlobals.Filter, &PasusGlobals.ClientPort);
        PasusGlobals.ClientPort = NULL;
    }
    if (PasusGlobals.ServerPort != NULL) {
        FltCloseCommunicationPort(PasusGlobals.ServerPort);
        PasusGlobals.ServerPort = NULL;
    }
}

NTSTATUS
PasusSendScanRequest(
    _In_ PPASUS_SCAN_REQUEST Request,
    _Out_ PPASUS_SCAN_VERDICT Verdict
    )
{
    NTSTATUS status;
    LARGE_INTEGER timeout;
    ULONG replyLength = sizeof(PASUS_SCAN_VERDICT);

    RtlZeroMemory(Verdict, sizeof(PASUS_SCAN_VERDICT));
    Verdict->Version = 1;
    Verdict->RequestId = Request->RequestId;
    Verdict->Action = PasusActionTimeoutAllow;
    Verdict->FinalVerdict = PasusVerdictUnknown;
    Verdict->Confidence = PasusConfidenceLow;

    if (PasusGlobals.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;
    }

    timeout.QuadPart = -(10 * 1000 * (LONGLONG)PasusGlobals.PreExecutionTimeoutMs);
    status = FltSendMessage(
        PasusGlobals.Filter,
        &PasusGlobals.ClientPort,
        Request,
        sizeof(PASUS_SCAN_REQUEST),
        Verdict,
        &replyLength,
        &timeout);

    if (status == STATUS_TIMEOUT) {
        Verdict->Action = PasusActionTimeoutAllow;
        Verdict->FinalVerdict = PasusVerdictUnknown;
        Verdict->Confidence = PasusConfidenceLow;
    }

    return status;
}
