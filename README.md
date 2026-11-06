# OPSLI `opsli-boot` HTML Upload Stored XSS

## Summary

`opsli-boot` 2.2 permits an authenticated low-privilege user to upload an
HTML document through the OSS upload endpoint when local object storage is
enabled. The uploaded file is placed under `/static/files/`, can be retrieved
without authentication, and is served with `Content-Type: text/html`.

Because the file is served from the same origin as the administration UI,
JavaScript in the uploaded document executes in the application origin. The
official UI stores its access token in
`localStorage["opsli-token"]`, so script running in that origin can read the
token and issue authenticated requests as the victim.

This is a stored cross-site scripting issue reached through unrestricted
upload of an active file type.

## Affected product

- Vendor/project: `hiparker`
- Product: `opsli-boot`
- Version: `2.2`
- Tested revision:
  `603d8a6ad001e91d265543259a357f8134c45549`
- Official frontend revision:
  `2c98b5249fa82ee2d0210e101ffd0b71036ac8dc`

Required configuration:

- The application has at least one valid low-privilege account.
- The storage type is `local`.
- `/static/files/**` remains publicly readable, as in the supplied
  configuration.

## Impact

A low-privilege authenticated user can publish persistent active content in
the application origin. When an administrator opens the generated URL, the
uploaded JavaScript can:

- read the access token from `localStorage["opsli-token"]`;
- invoke APIs with the visitor's privileges;
- read, create, update, or delete application objects allowed by that token.

The PoC in this repository does not transmit, print, or otherwise retain a
real token. It only demonstrates that same-origin JavaScript can read a
present token.

## Classification and score

- Primary CWE: CWE-434, Unrestricted Upload of File with Dangerous Type
- Secondary CWE: CWE-79, Improper Neutralization of Input During Web Page
  Generation (Cross-site Scripting)
- CVSS 4.0: `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`
- CVSS 4.0 base score: **8.5 High**

`PR:L` reflects that the uploader must have a valid low-privilege account.
`UI:P` reflects that a victim must open the stored HTML URL. `VI:H` reflects
that script in the victim origin can perform state-changing actions with the
victim's token.

## Vulnerable code

Upload endpoint has no file-type or permission check beyond authentication:

- <https://github.com/hiparker/opsli-boot/blob/603d8a6ad001e91d265543259a357f8134c45549/opsli-modulars/opsli-modulars-system/src/main/java/org/opsli/modulars/tools/oss/web/OssRestController.java#L41-L64>

The original extension is appended to the generated file name:

- <https://github.com/hiparker/opsli-boot/blob/603d8a6ad001e91d265543259a357f8134c45549/opsli-base-support/opsli-core/src/main/java/org/opsli/plugins/oss/service/BaseOssStorageService.java#L77-L107>

The local storage implementation writes the uploaded content beneath
`/static/files/`:

- <https://github.com/hiparker/opsli-boot/blob/603d8a6ad001e91d265543259a357f8134c45549/opsli-base-support/opsli-core/src/main/java/org/opsli/plugins/oss/service/impl/LocalStorageServiceImpl.java#L117-L167>

The uploaded directory is exposed as a static resource and the files path is
left outside authentication and WAF checks:

- <https://github.com/hiparker/opsli-boot/blob/603d8a6ad001e91d265543259a357f8134c45549/opsli-starter/src/main/resources/application.yaml#L57>
- <https://github.com/hiparker/opsli-boot/blob/603d8a6ad001e91d265543259a357f8134c45549/opsli-starter/src/main/resources/application.yaml#L195>
- <https://github.com/hiparker/opsli-boot/blob/603d8a6ad001e91d265543259a357f8134c45549/opsli-starter/src/main/resources/application.yaml#L205>

The official UI stores the access token in `localStorage`:

- <https://github.com/hiparker/opsli-ui/blob/2c98b5249fa82ee2d0210e101ffd0b71036ac8dc/vue-admin-better/src/config/setting.config.js#L37-L42>
- <https://github.com/hiparker/opsli-ui/blob/2c98b5249fa82ee2d0210e101ffd0b71036ac8dc/vue-admin-better/src/utils/accessToken.js#L31-L45>

## Environment

- JDK 21
- Maven-built `opsli-starter-1.6.2.jar`
- MySQL `8.x`
- Redis
- Base URL: `http://127.0.0.1:7000/opsli-boot`

The test uses a local, non-production database initialized from the
repository SQL. It does not target a third-party deployment.

## Reproduction

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Set the low-privilege test credentials. The repository's initialization SQL
contains a stock low-privilege account, but operators should use a dedicated
test account in their own environment.

```powershell
$env:OPSLI_URL = "http://127.0.0.1:7000/opsli-boot"
$env:OPSLI_USER = "songyi"
$env:OPSLI_PASS = "Aa123456."
python .\exp_upload_xss.py --output .\evidence.json
```

The script performs these checks:

1. Authenticates as the low-privilege user.
2. Confirms the account is not a super administrator.
3. Uploads `proof.html` through `/api/v1/tools/oss/upload`.
4. Uses a fresh HTTP session with no authentication to retrieve the returned
   URL.
5. Requires HTTP 200, `Content-Type: text/html`, and the PoC marker in the
   anonymously retrieved body.
6. Writes a machine-readable `evidence.json`.

Expected result:

```text
[+] low-privilege identity: songyi (superAdmin=False)
[+] uploaded URL: http://127.0.0.1:7000/opsli-boot/static/files/.../....html
[+] anonymous status: 200
[+] content type: text/html
[+] marker present: true
[+] evidence written: evidence.json
```

## Browser execution evidence

Open the uploaded URL in a browser. For a reproducible sentinel test:

1. Visit `http://127.0.0.1:7000/opsli-boot/`.
2. In the developer console, set a non-sensitive sentinel value:

   ```javascript
   localStorage.setItem("opsli-token", "CVE_AUDIT_SENTINEL");
   ```

3. Navigate to the uploaded URL.
4. The page reports `Stored XSS executed` and
   `localStorage token readable: YES`.

The included `proof.html` never sends data to an external host.

## Remediation

- Enforce an extension and MIME allowlist for uploads.
- Reject `html`, `htm`, `xhtml`, `svg`, and other script-capable types.
- Sniff and normalize the stored content type server-side.
- Store user uploads on a separate origin or serve them only with
  `Content-Disposition: attachment` and a non-document MIME type.
- Require an explicit upload permission rather than authentication alone.
- Move the access token out of JavaScript-readable storage where feasible.

## Disclosure

This material is for coordinated disclosure and CVE evidence. The uploaded
page is intentionally benign and does not attempt credential exfiltration or
modification of application data.
