# Limitations

No antivirus can truthfully guarantee 100% detection.

Current Pasus limitations:

- True pre-execution blocking on Windows requires a signed driver. Without it, Pasus uses user-mode post-launch termination.
- macOS blocking requires Endpoint Security entitlement and user approval.
- Linux blocking depends on fanotify permissions and kernel support.
- The bundled AI model is currently a development model and cannot auto-quarantine by itself.
- Encrypted files cannot always be restored without a Recovery Vault copy, OS snapshot, backup, or decryption key.
- Pasus uses EICAR and benign simulators for tests, not real malware samples.

Pasus must not claim a protection layer is active unless its health check proves it is active.
