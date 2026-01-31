# Security Audit Report

**Date:** 2025-05-20
**Target:** AliasVault Codebase
**Auditor:** Jules

## Executive Summary

This report details the findings of a comprehensive security review of the AliasVault password manager codebase. Several critical and high-severity vulnerabilities were identified, primarily related to server configuration and default security settings. These issues, if left unaddressed, could allow for unauthorized access, data exfiltration, or user enumeration.

## Findings

### 1. Permissive CORS Policy (High)

**Location:** `apps/server/AliasVault.Api/Program.cs`

**Issue:** The Cross-Origin Resource Sharing (CORS) policy is configured to allow any origin, method, and header (`AllowAnyOrigin`).

**Risk:** This configuration allows malicious websites to send requests to the AliasVault API on behalf of an authenticated user (if specific authentication methods relying on browser behavior were used, though Bearer tokens mitigate this slightly). More critically, it allows any site to perform timing attacks or probe the API structure. For a password manager, strict origin control is essential to prevent browser-based attacks.

**Recommendation:** Configure CORS to only allow trusted origins defined via environment variables (`ALLOWED_ORIGINS`).

### 2. IP Address Spoofing (Medium)

**Location:** `apps/server/Utilities/AliasVault.Auth/IpAddressUtility.cs`

**Issue:** The application manually parses the `X-Forwarded-For` header and blindly trusts the first IP address in the list.

**Risk:** An attacker can forge the `X-Forwarded-For` header to spoof their IP address. This bypasses security controls based on IP logging and auditing, making forensic analysis unreliable.

**Recommendation:** Use ASP.NET Core's built-in `ForwardedHeadersMiddleware` to safely handle proxy headers, trusting only the internal reverse proxy, and access `HttpContext.Connection.RemoteIpAddress`.

### 3. Weak Default Password Policy (High)

**Location:** `apps/server/AliasVault.Api/Program.cs`

**Issue:** The default `Identity` configuration allows for weak passwords (8 characters, no complexity requirements).

**Risk:** While the Master Password (used for encryption) is critical, the account password (used for authentication and SRP) is also a target. A weak password policy makes the system vulnerable to brute-force and dictionary attacks, potentially exposing the encrypted vault blob or allowing unauthorized account access.

**Recommendation:** Enforce a strong password policy: minimum 12 characters, requiring uppercase, lowercase, digits, and special characters.

### 4. JWT Signing Key Validation (High)

**Location:** `apps/server/Shared/AliasVault.Shared.Server/Utilities/SecretReader.cs`

**Issue:** The application reads the JWT signing key but does not validate its strength (length).

**Risk:** If a short or weak key is used (e.g., "secret"), attackers can brute-force the key offline and forge valid JWT tokens, granting full access to any user account.

**Recommendation:** Enforce a minimum length of 32 characters (256 bits) for the JWT signing key.

### 5. Information Leakage (Low)

**Location:** API Responses

**Issue:** The `Server` header (e.g., Kestrel) and specific version numbers in the `/status` endpoint are exposed.

**Risk:** Revealing specific server technologies and versions helps attackers tailor exploits for known vulnerabilities in those versions.

**Recommendation:** Disable the `Server` header in Kestrel configuration and consider restricting detailed version info.

## Remediation Plan

The following actions will be taken to address these issues:

1.  **CORS:** Implement configurable `AllowedOrigins` checking.
2.  **IP Handling:** Refactor `IpAddressUtility` to use `RemoteIpAddress` and configure `ForwardedHeadersOptions`.
3.  **Password Policy:** Strengthen `Identity` options in `Program.cs`.
4.  **JWT Security:** Add validation for key length in `SecretReader`.
5.  **Hardening:** Remove `Server` header.
