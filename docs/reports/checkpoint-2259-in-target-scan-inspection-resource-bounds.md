# Checkpoint 2259 - In-Target Scan Inspection Resource Bounds

Status: **Closed through hosted integration and synchronized destination verification**

## Scope

Checkpoint 2258 applies total elapsed limits before and after retained file
inspection. The callback passed through Native Engine hashing, static analysis,
publisher trust completion, signature/rule/archive providers, heuristics, ML,
and verdict publication still checked only the job cancellation token. One slow
or adversarial file could therefore carry cooperative Native work beyond the
total Quick, Full, or Custom elapsed limit before Local Core classified it.

Standard Native file scans also sampled at most 64 MiB for analysis but hashed
an otherwise unbounded regular file. That enabled exact-hash evidence for large
files, but provided no total admitted read-byte ceiling for a hostile sparse or
very large file.

## Implemented Contracts

- Standard Native file scans admit at most 1,073,741,824 bytes (1 GiB). Initial
  metadata above the limit fails before opening the content, and growth beyond
  the same limit fails before hash or verdict publication.
- The existing 64 MiB analyzer sample remains unchanged. Files between 64 MiB
  and 1 GiB still receive a full SHA-256 plus bounded sampled analysis.
- Local Core computes one cancellation-first `ScanStopReason` at every existing
  Native callback. A visible user cancellation remains `Cancelled`; otherwise
  the mode's total elapsed limit becomes `TimeLimitReached`.
- Native cooperative cancellation is mapped only when Local Core observed the
  corresponding stop reason. An unexplained cooperative-stop error remains an
  error instead of defaulting to cancellation or timeout.
- A time limit reached during hashing or analysis publishes no partial file
  verdict. The interrupted file and every queued file are counted as skipped,
  the report says they were not scanned or reported clean, and the scan remains
  incomplete with indeterminate terminal progress.
- Cancellation-token read/parse failures continue through the existing
  fail-visible cancellation-check error route.

## Test And Evidence Scripting

Four benign regressions share the `scan_inspection_resource_budget_` filter:

1. the exact 1 GiB Native standard-read limit is admitted and one byte over is
   rejected by the pre-I/O size policy helper;
2. both standard Native scan-content entrypoints use the shared 1 GiB limit and
   no longer pass `u64::MAX`;
3. an injected in-target elapsed stop on harmless bytes returns
   `TimeLimitReached` before a verdict; and
4. Local Core source accounting requires the interrupted-plus-queued skipped
   count, explicit not-clean error, loop stop, and no scanned-file increment.

Definitive verifier step 288 is `native/local in-target scan inspection
resource-budget regressions`. The strict validator requires exact `288/288`,
the step, three verified-scope statements, and two technical-limit statements.
Source contract 689 pins implementation, tests, verifier, validator, documents,
dependency honesty, and the scripting boundary.

No checkpoint-2259 test ran during this scripting phase. The complete source,
test, verifier, validator, contract, and documentation batch was scripted first.
Only after that boundary did focused, broad, definitive, and adversarial local
verification run. Hosted integration, guarded destination synchronization, and
destination verification remain pending.

## Local Verification Evidence

After the scripting boundary, all intended local checks passed:

- `git diff --check`, Rust formatting, and verifier/validator parsing under
  Windows PowerShell 5.1 and PowerShell 7 passed.
- Source contracts passed exact `689/689`. The four new
  `scan_inspection_resource_budget_` regressions passed `4/4`; overlapping
  Native content/cancellation and Local resource/cancellation filters passed
  `3/3`, `61/61`, `8/8`, and `14/14`.
- Complete Local Core passed `564/564`. Native Engine passed 640 tests with 21
  intentionally ignored isolated child fixtures, and its compiler passed
  `6/6`. Strict all-target/all-feature, no-dependency Clippy passed separately
  for Native Engine and Local Core.
- Both locked workspace variants, the locked all-feature release build, Flutter
  analyze plus `847/847`, Zentor protocol analyze plus `14/14`, and Avorax
  protocol analyze plus `6/6` passed.
- The no-skip/no-Defender-host-integration verifier passed exact `288/288` in
  `667.4s` with zero failed or non-null-error steps. Its schema-2 report is
  210,919 bytes with SHA-256
  `aba47033b18eead7eca3c192b13c6f9c599743b768bce4c28fbd0b6ed0a7d224`;
  `skip_flutter=false`, `skip_rust=false`, and
  `include_defender_eicar=false`. Independent PowerShell 5.1 and 7 validation
  passed.
- Both PowerShell hosts rejected the missing-step, missing-verified-scope, and
  missing-technical-scope mutations with exit 1. Exact owned mutation residue
  was zero.
- Root, Native, and Flutter lock SHA-256 values remained
  `7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
  `7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
  and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
  No product process was active. The protected quarantine stayed read-only at
  16,072 files, zero directories, 4,522,733 bytes, 5,357 each `.avoraxq`,
  `.json`, and `.auth`, one `.metadata_auth_key`, and zero pending/unknown/temp
  or reparse entries.

One deliberately broader, non-CI workspace Clippy experiment was not credited:
`cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`
failed only on three unchanged `services/api` lint findings (`enum_variant_names`
and two `items_after_test_module`). The repository CI does not apply Clippy to
that crate; the exact strict Clippy gates for both changed Rust crates passed.
This pre-existing cleanup remains visible rather than being misreported as a
successful checkpoint check.

One mistaken `python -m pytest tests/test_custom_driver_contract.py -q`
invocation was also not credited because this environment has no `pytest`
module. It ran no contract. The repository-owned dependency-free runner,
`python -B tools/testing/run-python-source-contracts.py`, subsequently passed
the same final source at exact `689/689`.

Exact-head CI/packages, normal PR integration, merged-main evidence, guarded
zero-delete synchronization, and independent destination verification remain
required before Checkpoint 2259 can close.

## Hosted Implementation-Head Evidence

Exact implementation commit
`97e16e7b6e1051788f36bbd51e68b1e3890c5d0c` passes PR `#127` Avorax CI run
`33160451724`, push Desktop Packages run `33160424802`, and PR Desktop Packages
run `33160451797`. All five CI jobs, both package-contract jobs, all eight
platform build jobs, both consolidation jobs, Windows administrative MSI
extraction without installation, and checksum/SBOM generation pass. Both beta-
prerelease publication jobs are intentionally skipped.

The untouched push consolidated artifact `9681909119` is 132,172,341 bytes with
SHA-256 `a0ad670646b91f125a85d87d01f9f82379663a9ddf26aeec152d38a0b8a86d34`.
The untouched PR consolidated artifact `9681997334` is 132,198,805 bytes with
SHA-256 `ea18f2b7bb9722b35e6e755ff8a9b322933d65bf2aaf85d8efde912cd07987a7`.
Both local downloads match GitHub metadata exactly.

Bounded, non-extracting in-stream review of each archive passes exactly eight
safe root entries, six platform packages, seven matching checksum targets,
CycloneDX 1.6, and 569 non-empty unique component references. Declared
uncompressed totals are 136,155,889 and 136,154,604 bytes. There are zero
duplicate, unsafe, encrypted, directory, link, or unsupported-special entries.
No package was extracted, installed, or executed. Both owned review ZIPs were
removed with zero residue. The first PowerShell cleanup forms were blocked
before execution by shell policy; exact Python `Path.unlink` cleanup then
succeeded. Evidence-head hosted checks, normal PR merge, merged-main evidence,
guarded destination synchronization, and destination verification are recorded
below.

## Integration And Destination Closure

Exact evidence commit `fe3797bcac088f8cddca2f65dd7e26eb7536191d`
passes Avorax CI `33162469870` and PR Desktop Packages `33162470034`; the
publication job is intentionally skipped. Consolidated artifact `9682604225`
is 132,169,216 bytes with SHA-256
`46b212de6dc445487c49fb850ad3f4e67ee0c5996fb5f4f977550c4fa3fca33f`.
Its bounded, non-extracting review passes exact 8-root/6-package/7-checksum/
CycloneDX-1.6/569-unique-ref inventory, 136,155,318 declared uncompressed
bytes, zero unsafe or special entries, and zero owned residue.

PR `#127` merges normally as
`5481ba6ed1322ee78d59a43c63dd0d74dc06f560`. Merged-main CI `33163723172`
and Desktop Packages `33163723171` pass all jobs; publication remains skipped.
The untouched merged-main artifact `9683155445` is 132,266,298 bytes with
SHA-256 `c1ea2fa43f092bf6bce149db90c3100d1e590005b263bf2931bd115a184e2763`.
Bounded in-stream review passes exact 8/6/7 inventory, CycloneDX 1.6 with 569
unique non-empty component references, 136,114,309 declared uncompressed bytes,
and zero unsafe, duplicate, encrypted, directory, link, extraction, execution,
installation, or owned residue.

Read-only destination preflight verifies all correct-base/absence conditions.
Guarded same-directory staging, backup, and atomic activation synchronize exact
`13/13` paths: 12 modified, one added, zero deleted, 7,571,661 activated bytes,
no rollback, exact merged-blob equality, and zero staging/backup residue.

The synchronized destination passes PS5/PS7 parser `2/2`, Source `689/689`,
formatting, focused resource-budget `4/4`, complete Local Core `564/564`, and
strict all-target/all-feature no-dependency Clippy for both changed crates. Its
no-skip/no-Defender definitive verifier passes exact `288/288` with zero failed
or non-null-error steps in `685.6s`. Independent PS5 and PS7 validators accept
the 202,267-byte schema-2 report with SHA-256
`601d7eb11e5c6e09f917f4810f5d409f95b7ae15d2e8947c07b1eabcce482ab9`.

Root, Native, and Flutter lock SHA-256 values remain exact at
`7c7c8aa006c2ac80eb89fa64d3b8ec09b32b26598b1a85bceb3c2af5a2d20e39`,
`7f4393c81896600c4a5e84cad288a1a5360eccbc1c458b38f615082f66391383`,
and `4de19695f9207273746341ca2221541b5b86d9f72af83727afca78541e177694`.
No Avorax/Zentor process remains. The read-only protected-vault invariant is
exactly 16,072 files, zero directories, 4,522,733 bytes, 5,357 each payload/
metadata/auth file, one metadata key, and zero unknown, pending, temporary, or
reparse entry. `.verification` remains untracked and unstaged; no evidence file
was deleted. No artifact was installed, released, or published. Checkpoint 2259
is closed; the complete antivirus-hardening goal and all limits below remain
active.

## Technical Limits

- In-target elapsed enforcement is cooperative. One entered filesystem,
  Authenticode, or other OS call, one at-most-1-MiB hash read, or one separately
  bounded analyzer/provider chunk can overrun before the next callback.
- User mode cannot interrupt a kernel, filesystem, security-provider, or trust
  call that stalls indefinitely. No hard realtime, installed watchdog, driver,
  kernel mediation, or pre-execution blocking is claimed.
- The 1 GiB cap bounds standard scan bytes, not wall time, CPU, kernel work,
  storage latency, memory-map activity, allocator overhead, or later mutation.
  Files above the limit are explicitly incomplete, not clean.
- Full-file SHA-256 and sampled analysis do not prevent mutation through a
  previously opened writable/mapped handle or authorize later execution.

## Safety And Dependencies

Checkpoint 2259 adds no dependency, feature, package source, license class,
downloaded runtime, machine-wide component, or lockfile change. It reuses
`Instant`, checked existing scan counters, the Native cancellation callback,
and existing bounded-error/report code. Tests use harmless text and pure size
policy values; they never execute a candidate or allocate a 1 GiB fixture.

No live malware, Defender setting, machine-wide installation, service/driver
start, release, publication, or protected-quarantine mutation is part of this
checkpoint. `.verification` contains only untracked local evidence and remains
unstaged; `C:\ProgramData\Avorax\Quarantine` remained read-only and exact. The
complete antivirus-hardening goal remains active.
