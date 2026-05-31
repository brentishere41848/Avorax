# Avorax AMSI Provider

Avorax will use AMSI for script/content scanning where feasible.

Current state:

- Design validation state only; no provider is registered by this repository yet.
- Avorax does not disable, replace, or bypass Windows Defender AMSI behavior.
- UI must not claim AMSI protection until a registered provider is installed and self-test passes.

Planned coverage:

- PowerShell encoded command indicators.
- VBScript/JScript suspicious script patterns.
- Office macro-like content passed through supported AMSI flows.
