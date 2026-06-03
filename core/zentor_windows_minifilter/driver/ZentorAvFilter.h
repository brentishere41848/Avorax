#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define ZENTOR_FILTER_PORT_NAME L"\\ZentorAvFilterPort"
#define ZENTOR_DEFAULT_TIMEOUT_MS 750
#define ZENTOR_MAX_PATH_CHARS 1024
#define ZENTOR_MAX_RENAME_TARGET_CHARS 512

typedef enum _ZENTOR_DRIVER_PROTECTION_MODE {
    ZentorModeDisabled = 0,
    ZentorModeObserveOnly = 1,
    ZentorModeBlockKnownBad = 2,
    ZentorModeBlockConfirmedThreats = 3,
    ZentorModeAggressive = 4
} ZENTOR_DRIVER_PROTECTION_MODE;

typedef enum _ZENTOR_SCAN_EVENT_TYPE {
    ZentorEventFileOpen = 0,
    ZentorEventFileCreate = 1,
    ZentorEventFileWrite = 2,
    ZentorEventFileRename = 3,
    ZentorEventImageExecuteAttempt = 4,
    ZentorEventSectionCreateAttempt = 5
} ZENTOR_SCAN_EVENT_TYPE;

typedef enum _ZENTOR_VERDICT_ACTION {
    ZentorActionAllow = 0,
    ZentorActionBlock = 1,
    ZentorActionQuarantine = 2,
    ZentorActionAllowAndMonitor = 3,
    ZentorActionTimeoutAllow = 4,
    ZentorActionTimeoutBlock = 5
} ZENTOR_VERDICT_ACTION;

typedef enum _ZENTOR_FINAL_VERDICT {
    ZentorVerdictClean = 0,
    ZentorVerdictLikelyClean = 1,
    ZentorVerdictUnknown = 2,
    ZentorVerdictObservation = 3,
    ZentorVerdictSuspicious = 4,
    ZentorVerdictProbableMalware = 5,
    ZentorVerdictConfirmedMalware = 6
} ZENTOR_FINAL_VERDICT;

typedef enum _ZENTOR_CONFIDENCE {
    ZentorConfidenceLow = 0,
    ZentorConfidenceMedium = 1,
    ZentorConfidenceHigh = 2,
    ZentorConfidenceConfirmed = 3
} ZENTOR_CONFIDENCE;

typedef struct _ZENTOR_SCAN_REQUEST {
    ULONG Version;
    ULONG RequestId;
    ZENTOR_SCAN_EVENT_TYPE EventType;
    ULONG ProcessId;
    ULONG ParentProcessId;
    ACCESS_MASK DesiredAccess;
    ULONG CreateDisposition;
    ULONG FileAttributes;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER TimestampUtc;
    WCHAR FilePath[ZENTOR_MAX_PATH_CHARS];
    WCHAR RenameTarget[ZENTOR_MAX_RENAME_TARGET_CHARS];
} ZENTOR_SCAN_REQUEST, *PZENTOR_SCAN_REQUEST;

typedef struct _ZENTOR_SCAN_VERDICT {
    ULONG Version;
    ULONG RequestId;
    ZENTOR_VERDICT_ACTION Action;
    ZENTOR_FINAL_VERDICT FinalVerdict;
    ZENTOR_CONFIDENCE Confidence;
    ULONG CacheTtlMs;
    BOOLEAN QuarantineAfterBlock;
    WCHAR Reason[256];
} ZENTOR_SCAN_VERDICT, *PZENTOR_SCAN_VERDICT;

typedef struct _ZENTOR_FILTER_GLOBALS {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    volatile LONG NextRequestId;
    ZENTOR_DRIVER_PROTECTION_MODE Mode;
    ULONG PreExecutionTimeoutMs;
} ZENTOR_FILTER_GLOBALS, *PZENTOR_FILTER_GLOBALS;

extern ZENTOR_FILTER_GLOBALS ZentorGlobals;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
ZentorCreateCommunicationPort(_In_ PDRIVER_OBJECT DriverObject);

VOID
ZentorCloseCommunicationPort(VOID);

NTSTATUS
ZentorSendScanRequest(
    _In_ PZENTOR_SCAN_REQUEST Request,
    _Out_ PZENTOR_SCAN_VERDICT Verdict
    );

FLT_PREOP_CALLBACK_STATUS
ZentorPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
ZentorPreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
ZentorPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
ZentorPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
ZentorUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

BOOLEAN
ZentorShouldExcludePath(_In_ PUNICODE_STRING NormalizedName);

BOOLEAN
ZentorIsCriticalSystemPath(_In_ PUNICODE_STRING NormalizedName);

NTSTATUS
ZentorBuildScanRequest(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ZENTOR_SCAN_EVENT_TYPE EventType,
    _Out_ PZENTOR_SCAN_REQUEST Request
    );

BOOLEAN
ZentorShouldBlockVerdict(_In_ PZENTOR_SCAN_VERDICT Verdict);
