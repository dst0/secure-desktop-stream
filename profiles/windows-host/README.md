# Profile: Windows Host (`windows-host`)

Hardened Windows 10/11 Sunshine host configuration with protected SDDL directory ACLs (current user + `SYSTEM` + `Administrators` only), `RemoteAddress`-scoped Defender Firewall rules, guided temporary `47989/tcp` pairing switches, and clean `-Uninstall` support.

## Generating a Concrete Instance Bundle

```bash
sds-installer gen-config \
  --profile windows-host \
  --controller-ip 192.168.1.10 \
  --out ./generated-windows-bundle
```
