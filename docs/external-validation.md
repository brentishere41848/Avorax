# External Validation

Avorax uses safe validation inputs only.

Supported checks:

- EICAR safe antivirus test file.
- AMTSO-style security feature checks where they use safe test content.
- Avorax harmless known-bad hash fixture.
- Avorax benign ransomware simulator in an isolated empty temporary test directory only; checkpoint 860 also requires exclusive flushed fixture writes/appends.

Do not add real malware samples to this repository.

Validation reports should record:

- Avorax version.
- Protection mode.
- Driver installed/running state.
- Guard service state.
- Whether the action happened before execution or after launch.
- Quarantine metadata path.
- False-positive result on benign fixtures.
- Performance impact.

External lab readiness requires measuring protection, performance, usability, false positives, on-execution protection, remediation, and ransomware recovery. Passing internal EICAR tests is not the same as independent certification.
