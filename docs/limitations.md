# Limitations

No antivirus can truthfully guarantee 100% detection.

Current Pasus limitations:

- Pasus Native Engine is the primary offline scanner. ClamAV and YARA compatibility paths are optional, disabled by default, and not required for scanning or quarantine.
- PNE does not execute suspicious files, upload files, or include real malware samples in the repository.
- True production pre-execution blocking on Windows requires a signed, installed, running driver with passing self-test. Without it, Pasus uses user-mode post-launch termination.
- Lockdown Mode improves prevention by blocking unknown apps, but true before-launch enforcement requires the active driver path.
- macOS blocking requires Endpoint Security entitlement and user approval.
- Linux blocking depends on fanotify permissions and kernel support.
- The bundled native ML model is currently a development model and cannot auto-quarantine by itself.
- Encrypted files cannot always be restored without a Recovery Vault copy, OS snapshot, backup, or decryption key.
- Pasus uses EICAR and benign simulators for tests, not real malware samples.
- v0.1.13 driver validation requires a Windows VM with Visual Studio Build Tools or EWDK, WDK tools, Administrator rights, and manual TESTSIGNING configuration.
- Pasus should not replace Microsoft Defender until production signing and independent validation are complete.

Pasus must not claim a protection layer is active unless its health check proves it is active.
