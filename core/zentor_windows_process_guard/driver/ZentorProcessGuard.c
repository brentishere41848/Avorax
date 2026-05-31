/*
 * Avorax Process Guard skeleton.
 *
 * This is a documented WDK project path for pre-execution/process creation
 * protection. The current production build must not claim this is active until
 * a signed driver is installed and the Guard Service health check confirms it.
 */

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    /*
     * Production implementation must register PsSetCreateProcessNotifyRoutineEx,
     * query Avorax Guard Service through a safe kernel/user-mode channel or
     * cache, and return deny only for confirmed malicious verdicts.
     */
    return STATUS_NOT_IMPLEMENTED;
}
