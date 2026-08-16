# Get-NdesNtlmDisclosure.ps1

[![PowerShell Gallery](https://img.shields.io/badge/PowerShell%20Gallery-Get--NdesNtlmDisclosure-blue)](https://www.powershellgallery.com/packages/Get-NdesNtlmDisclosure) [![License](https://img.shields.io/badge/License-MIT-green)](https://github.com/richardhicks/ndesntlm/blob/main/LICENSE) [![Version](https://img.shields.io/powershellgallery/v/Get-NdesNtlmDisclosure?label=Version&color=brightgreen)](https://www.powershellgallery.com/packages/Get-NdesNtlmDisclosure)

## Overview

> **Important:** This script is a diagnostic and security assessment tool. It sends a single, unauthenticated request to a Network Device Enrollment Service (NDES) server to determine whether the server discloses sensitive host and domain information. It only reads what the server willingly returns and makes no changes to the target.

This script tests an NDES server for NTLM information disclosure. It sends an unauthenticated NTLM type-1 (negotiate) message to the NDES SCEP administration endpoint (`/certsrv/mscep_admin`) over HTTPS and inspects the server's NTLM type-2 (challenge) response.

When NTLM is enabled, the type-2 challenge leaks sensitive details in its TargetInfo block without any authentication, including the server's NetBIOS and DNS computer names, the NetBIOS and DNS domain names, the DNS forest name, and the operating system version. An attacker can use this information to enumerate an organization's internal Active Directory namespace. The script surfaces exactly what an unauthenticated client can retrieve so the exposure can be assessed and remediated (for example, by disabling NTLM on the NDES endpoint).

## Requirements

- Windows PowerShell 5.1 or later
- `curl.exe` (included with Windows 10/11 and Windows Server 2019 and later)
- Network access to the target NDES server over HTTPS (TCP 443)

## Installation

### PowerShell Gallery

Install the script directly from the [PowerShell Gallery](https://www.powershellgallery.com/):

```powershell
Install-Script -Name Get-NdesNtlmDisclosure
```

To update an existing installation to the latest version:

```powershell
Update-Script -Name Get-NdesNtlmDisclosure
```

### GitHub

Alternatively, download the script directly from the [GitHub repository](https://github.com/richardhicks/ndesntlm) and run it from a local folder.

## Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `ComputerName` | Yes | One or more fully qualified domain names (FQDNs) of the NDES servers to test. The request is sent over HTTPS to the `/certsrv/mscep_admin` path on each host. Accepts a comma-separated list and input from the pipeline. |
| `SkipCertificateCheck` | No | Bypasses TLS certificate validation (`curl -k`). Use this when the NDES server presents a self-signed or otherwise untrusted certificate. |

## Output

The script returns a single, consistently shaped `PSCustomObject` per target with the following properties:

- **Target** — the full URL of the tested administration endpoint
- **Status** — the outcome of the test (information disclosed, no NTLM challenge offered, or an inconclusive/invalid response)
- **NetBIOS Computer Name**
- **NetBIOS Domain Name**
- **DNS Computer Name**
- **DNS Domain Name**
- **DNS Forest Name**
- **OS Version**

The disclosure fields are populated when the server leaks them and are `$null` otherwise. Because every result shares the same shape, piping multiple servers renders as one uniform table.

## Examples

Test the NDES administration endpoint on the specified server over HTTPS and return any disclosed host and domain information:

```powershell
.\Get-NdesNtlmDisclosure.ps1 -ComputerName ndes.corp.example.com
```

Test the NDES server while ignoring TLS certificate validation errors, which is useful when the server presents a self-signed or untrusted certificate:

```powershell
.\Get-NdesNtlmDisclosure.ps1 -ComputerName ndes.corp.example.com -SkipCertificateCheck
```

Test multiple NDES servers by passing a comma-separated list of FQDNs:

```powershell
.\Get-NdesNtlmDisclosure.ps1 -ComputerName ndes1.corp.example.com, ndes2.corp.example.com, ndes3.corp.example.com
```

Test multiple NDES servers by piping their FQDNs to the script:

```powershell
'ndes1.corp.example.com', 'ndes2.corp.example.com' | .\Get-NdesNtlmDisclosure.ps1
```

## Notes

### Interpreting Results

- **Information disclosed** — The server returned a valid NTLM type-2 challenge and leaked host and domain details. Remediate by disabling NTLM on the NDES SCEP administration endpoint.
- **No NTLM challenge offered** — The endpoint did not present an NTLM challenge and did not disclose any information.
- **Inconclusive** — The server advertised NTLM but did not return a type-2 payload on this attempt. This can happen intermittently, so repeat the test before drawing a conclusion.
- **Invalid response** — The server returned an NTLM value that failed validation (it did not contain a well-formed NTLM type-2 message). No information could be extracted; repeat the test before drawing a conclusion.
- **TLS certificate validation failed** — The request was not sent because the server's TLS certificate could not be validated (self-signed, name mismatch, or untrusted issuer). Disclosure cannot be assessed until the connection succeeds. Re-run with `-SkipCertificateCheck` to bypass certificate validation.
- **Request failed** — The request did not complete for another reason (for example, the host was unreachable or the connection was refused). The status includes the underlying `curl` exit code and error text. Resolve the connectivity issue and repeat the test.

### How It Works

The request is sent with `curl.exe` rather than `Invoke-WebRequest` so that the response headers, including the raw NTLM challenge, are captured verbatim. The script checks `curl`'s exit code first, so a request that never completes (such as a TLS certificate validation failure) is reported as inconclusive rather than mistaken for a server that did not disclose information. When the request succeeds, the script decodes the base64 challenge, validates the `NTLMSSP` signature and message type, and walks the TargetInfo AV_PAIR block to extract the disclosed fields.

## Additional Resources

- [Richard M. Hicks Consulting Blog](https://directaccess.richardhicks.com/)
- [NDES NTLM GitHub Repository](https://github.com/richardhicks/ndesntlm/)

## License

Licensed under the MIT License. See [LICENSE](https://github.com/richardhicks/ndesntlm/blob/main/LICENSE) for details.

## Author

**Richard Hicks**  
Richard M. Hicks Consulting, Inc.  
[rich@richardhicks.com](mailto:rich@richardhicks.com)  
[https://www.richardhicks.com/](https://www.richardhicks.com/)
