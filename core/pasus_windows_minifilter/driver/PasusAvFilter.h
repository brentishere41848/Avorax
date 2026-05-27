#pragma once

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define PASUS_FILTER_PORT_NAME L"\\PasusAvFilterPort"
#define PASUS_DEFAULT_TIMEOUT_MS 750
#define PASUS_MAX_PATH_CHARS 1024

typedef enum _PASUS_DRIVER_PROTECTION_MODE {
    PasusModeDisabled = 0,
    PasusModeObserveOnly = 1,
    PasusModeBlockKnownBad = 2,
    PasusModeBlockConfirmedThreats = 3,
    PasusModeAggressive = 4
} PASUS_DRIVER_PROTECTION_MODE;

typedef enum _PASUS_SCAN_EVENT_TYPE {
    PasusEventFileOpen = 0,
    PasusEventFileCreate = 1,
    PasusEventFileWrite = 2,
    PasusEventFileRename = 3,
    PasusEventImageExecuteAttempt = 4,
    PasusEventSectionCreateAttempt = 5
} PASUS_SCAN_EVENT_TYPE;

typedef enum _PASUS_VERDICT_ACTION {
    PasusActionAllow = 0,
    PasusActionBlock = 1,
    PasusActionQuarantine = 2,
    PasusActionAllowAndMonitor = 3,
    PasusActionTimeoutAllow = 4,
    PasusActionTimeoutBlock = 5
} PASUS_VERDICT_ACTION;

typedef enum _PASUS_FINAL_VERDICT {
    PasusVerdictClean = 0,
    PasusVerdictLikelyClean = 1,
    PasusVerdictUnknown = 2,
    PasusVerdictObservation = 3,
    PasusVerdictSuspicious = 4,
    PasusVerdictProbableMalware = 5,
    PasusVerdictConfirmedMalware = 6
} PASUS_FINAL_VERDICT;

typedef enum _PASUS_CONFIDENCE {
    PasusConfidenceLow = 0,
    PasusConfidenceMedium = 1,
    PasusConfidenceHigh = 2,
    PasusConfidenceConfirmed = 3
} PASUS_CONFIDENCE;

typedef struct _PASUS_SCAN_REQUEST {
    ULONG Version;
    ULONG RequestId;
    PASUS_SCAN_EVENT_TYPE EventType;
    ULONG ProcessId;
    ULONG ParentProcessId;
    ACCESS_MASK DesiredAccess;
    LARGE_INTEGER FileSize;
    LARGE_INTEGER TimestampUtc;
    WCHAR FilePath[PASUS_MAX_PATH_CHARS];
} PASUS_SCAN_REQUEST, *PPASUS_SCAN_REQUEST;

typedef struct _PASUS_SCAN_VERDICT {
    ULONG Version;
    ULONG RequestId;
    PASUS_VERDICT_ACTION Action;
    PASUS_FINAL_VERDICT FinalVerdict;
    PASUS_CONFIDENCE Confidence;
    ULONG CacheTtlMs;
    BOOLEAN QuarantineAfterBlock;
    WCHAR Reason[256];
} PASUS_SCAN_VERDICT, *PPASUS_SCAN_VERDICT;

typedef struct _PASUS_FILTER_GLOBALS {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    volatile LONG NextRequestId;
    PASUS_DRIVER_PROTECTION_MODE Mode;
    ULONG PreExecutionTimeoutMs;
} PASUS_FILTER_GLOBALS, *PPASUS_FILTER_GLOBALS;

extern PASUS_FILTER_GLOBALS PasusGlobals;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
PasusCreateCommunicationPort(_In_ PDRIVER_OBJECT DriverObject);

VOID
PasusCloseCommunicationPort(VOID);

NTSTATUS
PasusSendScanRequest(
    _In_ PPASUS_SCAN_REQUEST Request,
    _Out_ PPASUS_SCAN_VERDICT Verdict
    );

FLT_PREOP_CALLBACK_STATUS
PasusPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
PasusPreAcquireForSectionSync(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

NTSTATUS
PasusUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

BOOLEAN
PasusShouldExcludePath(_In_ PUNICODE_STRING NormalizedName);

BOOLEAN
PasusIsCriticalSystemPath(_In_ PUNICODE_STRING NormalizedName);

NTSTATUS
PasusBuildScanRequest(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PASUS_SCAN_EVENT_TYPE EventType,
    _Out_ PPASUS_SCAN_REQUEST Request
    );

BOOLEAN
PasusShouldBlockVerdict(_In_ PPASUS_SCAN_VERDICT Verdict);
