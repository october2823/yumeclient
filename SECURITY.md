# Security policy

**English** | [Русский](SECURITY.ru.md)

## Supported versions

Fixes go into the next release. Older versions are not patched, so use the latest version from
[PyPI](https://pypi.org/project/yumeclient/).

| Version | Security fixes |
|---|---|
| 0.8.x | yes |
| older | no |

## Reporting a vulnerability

Do not open a public issue. Report it privately on GitHub: the **Security** tab of the
repository, **Report a vulnerability**
([direct link](https://github.com/october2823/yumeclient/security/advisories/new)). Only you and
the maintainers see the report. Include the yumeclient version, the OS, the steps or code to
reproduce it, and what an attacker gains.

## What counts

For example:

- a TLS certificate that is not checked although `verify` is on;
- credentials or cookies sent to a host they do not belong to (after a redirect, through a
  proxy);
- secrets left in the output of `r.trace()` or of `export_profile()` without
  `include_secrets=True`;
- a crash or memory corruption in the native library caused by what a server or proxy sends.

Not a vulnerability: a site that detects yumeclient (open a "Fingerprint mismatch" issue
instead). A bug that also exists in the upstream modules (bogdanfinn/tls-client, uTLS, quic-go)
should be reported upstream as well.
