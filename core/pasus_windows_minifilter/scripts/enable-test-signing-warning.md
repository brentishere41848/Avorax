# Windows Test-Signing Warning

Pasus does not enable Windows test-signing automatically.

Only enable test-signing inside a development VM used for driver testing. Test-signed kernel drivers are not appropriate for normal user machines.

To enable test-signing manually in a VM:

```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

To disable it after testing:

```powershell
bcdedit /set testsigning off
shutdown /r /t 0
```

Production releases require Microsoft driver signing. Pasus must not claim production pre-execution blocking from a test-signed development driver.
