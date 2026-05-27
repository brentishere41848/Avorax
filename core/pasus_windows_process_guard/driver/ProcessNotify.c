#include "PasusProcessGuard.h"

VOID
PasusProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);

    if (CreateInfo == NULL) {
        return;
    }

    /*
     * This first callback driver only establishes the real process creation
     * notification path. Denial must be enabled only after a signed driver can
     * consult a verified Guard Service cache without blocking the kernel path.
     */
    return;
}
