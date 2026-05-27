#include "PasusAvFilter.h"

BOOLEAN
PasusShouldBlockVerdict(_In_ PPASUS_SCAN_VERDICT Verdict)
{
    if (Verdict == NULL) {
        return FALSE;
    }

    if (PasusGlobals.Mode == PasusModeObserveOnly || PasusGlobals.Mode == PasusModeDisabled) {
        return FALSE;
    }

    if (Verdict->Action == PasusActionBlock || Verdict->Action == PasusActionQuarantine) {
        return Verdict->FinalVerdict == PasusVerdictConfirmedMalware ||
               Verdict->FinalVerdict == PasusVerdictProbableMalware;
    }

    if (Verdict->Action == PasusActionTimeoutBlock) {
        return PasusGlobals.Mode == PasusModeAggressive;
    }

    return FALSE;
}
