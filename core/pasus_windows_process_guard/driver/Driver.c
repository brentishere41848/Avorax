#include "PasusProcessGuard.h"

static BOOLEAN g_CallbackRegistered = FALSE;

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = PasusProcessGuardUnload;

    status = PsSetCreateProcessNotifyRoutineEx(PasusProcessNotify, FALSE);
    if (NT_SUCCESS(status)) {
        g_CallbackRegistered = TRUE;
    }

    return status;
}

VOID
PasusProcessGuardUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_CallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(PasusProcessNotify, TRUE);
        g_CallbackRegistered = FALSE;
    }
}
