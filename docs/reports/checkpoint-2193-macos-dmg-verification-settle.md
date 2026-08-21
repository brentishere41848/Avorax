# Checkpoint 2193 macOS DMG Verification Settle

## Scope

This checkpoint addresses one reproducible hosted-package availability race.
It does not change scanning, verdict thresholds, quarantine behavior,
definitions, service registration, driver state, Microsoft Defender, package
signing identity, or release publication.

The affected surface is `installer/macos/build-macos.sh` after `hdiutil create`
and before mandatory `hdiutil verify`. The central verification suite now also
requires the existing desktop package source-contract suite.

## Failure Evidence

Checkpoint 2192 merged as `71887973206f5287ba50cc8ff6e5eadcf43c678b`.
Merged-main Avorax CI run `32381508352` passed. Desktop Packages run
`32381508319` attempt 1 produced this split result:

| Job | ID | Result |
| --- | ---: | --- |
| Package contracts | `96465582183` | passed |
| Linux x64 DEB and tar | `96465644947` | passed |
| macOS x64 DMG | `96465644987` | passed |
| Windows x64 MSI and EXE | `96465645066` | passed |
| macOS arm64 DMG | `96465645009` | failed |
| Consolidate and checksum | `96471057508` | skipped after dependency failure |
| Publish desktop beta prerelease | `96471057886` | skipped |

The arm64 job had already passed app construction, ad-hoc signing, entitlement
inspection, manifest verification, mounted payload verification, and DMG
creation. The relevant timestamps were:

| Event | UTC timestamp | Result |
| --- | --- | --- |
| DMG created | `2026-08-20T14:48:00.7588840Z` | create succeeded |
| Verify attempt 1 | `2026-08-20T14:48:00.8182550Z` | resource temporarily unavailable |
| Verify attempt 2 | `2026-08-20T14:48:02.9980220Z` | resource temporarily unavailable |
| Verify attempt 3 | `2026-08-20T14:48:07.1962030Z` | resource temporarily unavailable |

The first verify began about 0.06 seconds after creation. Each failed with
`unable to recognize ... as a disk image` and the exact parenthetical/resource
error `Resource temporarily unavailable`. The package job failed; no exception
was swallowed and no success was recorded.

Failed-job rerun attempt 2 used unchanged source and passed. Arm64 job
`96772353094` created the DMG at `2026-08-21T12:45:08.6481380Z`; its first and
only verification attempt began at `2026-08-21T12:45:11.1254510Z`, about 2.5
seconds later. Consolidation job `96774515074` passed and publication job
`96774649572` was intentionally skipped. The full rerun concluded success.

This A/B evidence supports a hosted image-settle race. It does not establish
that every `hdiutil` failure is transient.

## Implementation

After DMG creation the builder now:

1. calls `sync`;
2. waits three seconds;
3. runs `hdiutil verify` up to five times;
4. retries only when captured output contains the exact
   `Resource temporarily unavailable` text;
5. waits 2, 4, 8, then 16 seconds between those transient attempts;
6. returns immediately for success or any non-transient failure;
7. returns the actual fifth-attempt status after budget exhaustion.

The fixed settle plus retry delays add at most 33 seconds. Output from every
attempt remains appended to `hdiutil-verify.txt`. Existing mounted payload,
manifest, code-signature, Gatekeeper, checksum, lifecycle, and cleanup checks
remain unchanged and fail visible.

The central verifier now records `Desktop package builder source contracts` as
a required step and describes bounded macOS DMG retries in verified scope. The
independent report validator requires both.

## Local Verification

Commands run from the repository root:

```powershell
python -B -m unittest discover -s tests -p test_packaging_tools.py -v
python -B tools\testing\run-python-source-contracts.py
C:\Program Files\Git\bin\bash.exe -n installer/macos/build-macos.sh
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\verify-small-threat-mvp.ps1 -PythonPath C:\Users\Brent\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe -CargoPath C:\Users\Brent\.cargo\bin\cargo.exe -FlutterPath C:\Users\Brent\develop\flutter\bin\flutter.bat -DartPath C:\Users\Brent\develop\flutter\bin\dart.bat -ReportPath .verification\checkpoint-2193-small-threat-mvp-definitive-report.json
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tools\testing\validate-small-threat-mvp-report.ps1 -RepoRoot (Get-Location).Path -ReportPath .verification\checkpoint-2193-small-threat-mvp-definitive-report.json -RequireFullSuite
```

Results:

- packaging: 24 executed, 21 passed, 3 explicit Windows symlink-privilege
  skips;
- Python source contracts: `626/626`;
- Bash syntax and both modified PowerShell parser checks: passed;
- definitive central report: `222/222`, zero failed report steps, empty error,
  from `2026-08-21T12:43:18.0517012Z` through
  `2026-08-21T12:52:31.8582905Z`, `553.8s`;
- independent full-report validator: passed in `1.5s`;
- stale checkpoint-2192 report: rejected because it omitted the new package
  step;
- `git diff --check`: passed;
- `Cargo.lock`: unchanged.

Read-only ProgramData quarantine inventory before and after the suite remained
16,072 files, zero directories, 4,522,733 bytes, 5,357 complete
payload/metadata/auth sets, one metadata-auth key, and zero pending files. No
vault content was modified or deleted.

## Hosted Status

Implementation commit `07e803c42880e7bc556642e206828f4e5c33b815` is on
draft PR `#45`. Exact-head Avorax CI `32484140638` passes all five jobs.

Desktop Packages push run `32484112523` passes:

| Job | ID | Result |
| --- | ---: | --- |
| Package contracts | `96776686153` | passed |
| Linux x64 DEB and tar | `96776731526` | passed |
| Windows x64 MSI and EXE | `96776731531` | passed |
| macOS arm64 DMG | `96776731584` | passed |
| macOS x64 DMG | `96776731596` | passed |
| Consolidate and checksum | `96780217485` | passed |
| Publish desktop beta prerelease | `96780340949` | skipped |

Desktop Packages PR run `32484140672` passes:

| Job | ID | Result |
| --- | ---: | --- |
| Package contracts | `96776769658` | passed |
| Linux x64 DEB and tar | `96776800887` | passed |
| Windows x64 MSI and EXE | `96776800856` | passed |
| macOS arm64 DMG | `96776801000` | passed |
| macOS x64 DMG | `96776800886` | passed |
| Consolidate and checksum | `96780488329` | passed |
| Publish desktop beta prerelease | `96780547410` | skipped |

All four changed-code macOS jobs logged `Attempt 1/5`, emitted no transient
resource-busy response, verified the image, and uploaded evidence. The push
arm64/x64 jobs left about 6.4/7.0 seconds between DMG creation and first
verification; PR arm64/x64 left about 6.1/5.8 seconds. This proves the settle
path executed natively on both architectures. No package was installed,
published, or released.

## Classification

- **Verified locally:** exact transient classification, bounded settle/backoff,
  non-transient immediate failure, retry-budget failure, package source
  contracts, central verifier integration, and independent report validation.
- **Verified hosted at exact implementation head:** Avorax CI, Windows, Linux,
  macOS arm64/x64, package contracts, and consolidation pass in push and PR
  workflows; publication is skipped.
- **Blocked:** Developer ID signing, notarization, installed package
  click-through, protected signing credentials, and production approval.
- **Technically limited:** DMG construction is package evidence only. It does
  not prove installed persistent monitoring, service/driver operation, kernel
  interception, Defender replacement, pre-execution blocking, or detection
  rate.

Standard Defender/EICAR integration was omitted. Only safe simulator and benign
fixtures were used. No package was installed, published, or released.
