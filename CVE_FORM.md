# CVE Form Fill

## Problem type

Primary:

- `CWE-434`: Unrestricted Upload of File with Dangerous Type

Add as a secondary weakness if the form supports multiple problem types:

- `CWE-79`: Improper Neutralization of Input During Web Page Generation
  (Cross-site Scripting)

If the form allows only one value, choose `CWE-434`.

## Affected product

- Vendor or product: `hiparker/opsli-boot`
- Product name: `opsli-boot`
- Source code repository: `https://github.com/hiparker/opsli-boot`
- Platform: `Java`, `Spring Boot`
- Affected status: `Yes`
- Version: `2.2`
- Version end: leave blank for the exact `2.2` release, unless the CVE editor
  requires a range
- Version type: `semver`
- Default status: `No`, because the issue depends on the affected version and
  local-storage configuration

If the version UI requires an upper bound, use:

- Version start: `2.2`
- Version end: `2.2`
- Version type: `semver`

## Vulnerability description

OPSLI opsli-boot 2.2, when configured with local object storage, allows an
authenticated low-privilege user to upload an HTML document through the OSS
upload endpoint. The file is stored under /static/files/, is publicly
retrievable without authentication, and is served with Content-Type
text/html. Attacker-supplied JavaScript therefore executes in the application
origin when a victim opens the generated URL, and can read the access token
that the official UI stores in localStorage.

## Tags

```text
stored xss
unrestricted file upload
html upload
localstorage token
opsli
```

## References

After publishing the evidence repository, add:

`https://github.com/shiyouxiaomi/opsli-boot-html-upload-stored-xss`

Also add:

`https://github.com/hiparker/opsli-boot`

Replace the first URL if the repository is published under a different name.

## Metrics

Select `CVSS v4.0`:

```text
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
```

- Base score: `8.5`
- Severity: `High`

Selected values:

- Attack Vector: Network
- Attack Complexity: Low
- Attack Requirements: None
- Privileges Required: Low
- User Interaction: Passive
- Confidentiality: High
- Integrity: High
- Availability: None
- Subsequent Confidentiality / Integrity / Availability: None

Do not use the currently displayed `10 Critical` score. The XSS proof does not
establish an availability impact, so `VA:N` is the defensible value.

## Required configuration

```text
The affected deployment must use local object storage and expose
/static/files/** without authentication. The attacker needs a valid
low-privilege account. The victim must open the generated uploaded-file URL.
```

## Exploit status

Select `Proof of Concept`.

## Solution

Reject active file types such as HTML and SVG, enforce extension and MIME
allowlists, serve uploads from a separate origin, and return untrusted files
with Content-Disposition: attachment and a non-document MIME type.

## Workaround

Disable local upload storage or require authentication and authorization for
every uploaded-file request. Do not host user uploads from the administration
UI origin.
