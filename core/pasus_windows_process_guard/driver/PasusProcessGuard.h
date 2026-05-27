#pragma once

#include <ntddk.h>

#define PASUS_PROCESS_GUARD_DEVICE_NAME L"\\Device\\PasusProcessGuard"
#define PASUS_PROCESS_GUARD_DOS_NAME L"\\DosDevices\\PasusProcessGuard"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD PasusProcessGuardUnload;

VOID
PasusProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );
