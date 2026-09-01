---
title: "Manual Application Testing"
description: "Manual checklist for testing Web Applications."
pubDate: "Jul 14 2025"
heroImage: "/blog-placeholder-3.jpg"
---

# Application Security Testing Checklist & Manual

---

## Part 1: Guide for Security Checks Using Developer Tools

### Overview & Documentation Guidelines
For each test case, capture representative screenshots and sample findings. Document both the current application behavior and the required secure baseline configuration. Highlight any missing controls, weak configurations, or actionable vulnerabilities.

---

### 1. HTTP Security Headers
**Steps:**
1. Open Developer Tools (`F12` or `Ctrl+Shift+I`).
2. Navigate to the **Network** tab.
3. Reload the page to capture initial network traffic.
4. Select the primary document request (typically the first entry).
5. In the **Headers** panel, inspect **Response Headers** for the following standard baselines and banner disclosures:

#### Recommended Response Headers

* `Content-Security-Policy: frame-ancestors 'none';`
  * **Purpose:** Defines which origins are permitted to embed the page in `<frame>`, `<iframe>`, `<embed>`, or `<object>` elements.
  * **Guidance:** Prevents framing from any domain. Recommended unless explicit framing requirements exist.

* `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  * **Purpose:** Forces web browsers to interact with the application exclusively over encrypted HTTPS connections.
  * **Guidance:** Eliminates HTTP-to-HTTPS redirect reliance and mitigates SSL stripping attacks.

* `X-Frame-Options: DENY`
  * **Purpose:** Legacy clickjacking protection mechanism that instructs supporting browsers to block framing.
  * **Guidance:** CSP `frame-ancestors` obsoletes `X-Frame-Options` in modern browsers. `X-Frame-Options` is only effective on interactive HTTP responses; it offers no defense on redirects or raw API payload responses (e.g., JSON/XML). Use CSP where possible while maintaining `DENY` for legacy compatibility.

* `X-Content-Type-Options: nosniff`
  * **Purpose:** Prevents browsers from MIME-sniffing a response away from the declared `Content-Type`.
  * **Guidance:** Forces strict adherence to declared content types, mitigating executable script injection via uploaded or static non-executable assets.

* `Referrer-Policy: strict-origin-when-cross-origin`
  * **Purpose:** Governs how much referrer path information is transmitted in the `Referer` request header.
  * **Guidance:** Ensures full URIs are sent cross-origin only over HTTPS, restricting cross-origin requests to origin-only data. Send this header across all endpoints to guarantee consistent fallback across legacy browser versions.

* `Permissions-Policy: geolocation=(), camera=(), microphone=()`
  * **Purpose:** Selectively enables or disables browser hardware APIs and feature capabilities.
  * **Guidance:** Disable all non-essential browser features at the root level, or restrict permissions strictly to authorized origins.

* `Access-Control-Allow-Origin: <origin>`
  * **Purpose:** Specifies which cross-origin targets can access application resources.
  * **Guidance:** Restrict origin reflection to explicitly trusted domain sets. Avoid wildcard (`*`) entries on endpoints processing authenticated contexts.

#### Banner Disclosures & Technology Fingerprinting
* Ensure server technology disclosure headers (e.g., `X-Powered-By`, `Server`, `X-AspNet-Version`) are suppressed or stripped across all responses.

---

### 2. Cookie Security Attributes
**Steps:**
1. In the **Network** tab, select a request and inspect the **Response Headers** for `Set-Cookie`.
2. Alternatively, navigate to the **Application** (or **Storage**) tab.
3. Expand **Cookies** under the **Storage** section.
4. Verify every session and application cookie for required flags:
   * `Secure`: Forces transmission exclusively over encrypted HTTPS connections.
   * `HttpOnly`: Blocks client-side scripts from accessing cookie tokens via `document.cookie`.
   * `SameSite`: Configured to `Strict` or `Lax` to mitigate Cross-Site Request Forgery (CSRF).
5. Document any cookies missing mandatory safety flags.

---

### 3. HTTPS and Mixed Content
**Steps:**
1. Verify the address bar URI schema starts explicitly with `https://`.
2. Review the **Console** tab for active or passive mixed content warnings.
3. In the **Network** tab, apply an `http://` filter to detect unencrypted HTTP subresource requests.
4. Document all insecure assets or plain-text protocol transmissions.

---

### 4. Source Code Exposure (Source Maps, Sensitive Data)
**Steps:**
1. Filter the **Network** tab traffic by `.js` or `.map`.
2. Determine if JavaScript source map files (`.map`) are publicly accessible.
3. Search files in the **Sources** tab for:
   * Hardcoded credentials, API keys, private tokens, or connection strings.
   * Internal developer comments containing sensitive logic details.
4. Document any exposed client-side code structures or secrets.

---

### 5. DOM and Client-Side Validation
**Steps:**
1. Open the **Elements** tab to inspect input form elements.
2. Check for HTML5 client-side constraints (e.g., `required`, `pattern`, `maxlength`).
3. Attempt form submissions using invalid inputs directly, then bypass client-side rules via proxy tools.
4. Review validation logic routines within the **Console** and **Sources** tabs.
5. Document missing, redundant, or easily bypassed client-side input validations.

---

### 6. DOM-Based XSS Checks
**Steps:**
1. Inspect the **Elements** and **Sources** tabs for dangerous sinks and handlers:
   * Inline event handlers (e.g., `onclick`, `onerror`, `onload`).
   * Execution sinks such as `innerHTML`, `outerHTML`, `document.write()`, or `eval()`.
2. Inject benign test vectors (e.g., `<img src=x onerror=alert(1)>`) into input parameters and DOM locations.
3. Determine if untrusted inputs are written directly to the DOM without proper context-aware encoding.
4. Document any successful script executions or unmanaged sinks.

---

### 7. Session Management
**Steps:**
1. Review active storage locations in the **Application/Storage** tab.
2. Ensure sensitive authentication tokens are stored securely (avoiding client-readable `localStorage`).
3. Verify session timeout limits by leaving client connections idle.
4. Attempt to replay revoked session tokens following logout actions.
5. Document weak session retention or improper storage implementation.

---

### 8. API Endpoints and Sensitive Data Exposure
**Steps:**
1. In the **Network** tab, filter requests using `XHR` or `Fetch`.
2. Review API payloads and response bodies for:
   * Excessive data disclosures (e.g., exposed PII, unhashed secrets, internal identifiers).
   * Sensitive parameter values transmitted in URL query strings rather than POST request bodies.
3. Document any instances of API data over-exposure.

---

### 9. CORS Policy
**Steps:**
1. Filter and select API transactions in the **Network** tab.
2. Review **Response Headers** for Cross-Origin Resource Sharing controls (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`).
3. Confirm that sensitive endpoints restrict cross-origin access exclusively to verified, trusted domains.
4. Document wildcard origins (`*`) or insecure `null` origin reflection settings.

---

### 10. Error Handling and Information Disclosure
**Steps:**
1. Submit malformed data, unexpected data types, or out-of-bounds parameters to application endpoints.
2. Review server status codes and payload responses in the **Network** tab.
3. Check the browser **Console** for unhandled client-side exceptions.
4. Document verbose error responses that expose stack traces, database details, file paths, or infrastructure data.

---

### 11. Third-Party Scripts and Resources
**Steps:**
1. Filter the **Network** tab by `JS` or `Script`.
2. Map all external dependencies and resource origin domains.
3. Inspect the **Elements** tab for external `<script>` loading tags.
4. Document untrusted third-party dependencies or missing Subresource Integrity (`sri`) attributes.

---

### 12. Local Storage, Session Storage, and IndexedDB
**Steps:**
1. Access the **Application/Storage** panel and inspect:
   * **Local Storage**
   * **Session Storage**
   * **IndexedDB**
2. Scan key-value pairs for stored access tokens, sensitive PII, or application secrets.
3. Document any unencrypted sensitive data stored locally on the client.

---

### 13. Autocomplete and Password Field Security
**Steps:**
1. Inspect sensitive input fields in the **Elements** tab.
2. Verify that sensitive inputs specify `type="password"`.
3. Check for `autocomplete="off"` or explicit auto-fill suppression attributes on sensitive fields.
4. Document improper or missing input safety attributes.

---

### 14. Cache Control
**Steps:**
1. Inspect the **Response Headers** of sensitive, authenticated pages in the **Network** tab for:
   * `Cache-Control: no-store, no-cache, must-revalidate`
   * `Pragma: no-cache`
   * `Expires: 0`
2. Ensure sensitive data is prohibited from being stored in client or proxy caches.
3. Document missing cache restriction directives on sensitive views.

---

### 15. Clickjacking Protections
**Steps:**
1. Inspect response headers for active framing restrictions:
   * `X-Frame-Options: DENY` or `SAMEORIGIN`
   * `Content-Security-Policy: frame-ancestors 'none'` (or explicitly authorized domain lists).
2. Validate that page views cannot be embedded inside external framing containers.
3. Document any endpoints missing clickjacking countermeasures.

---

### 16. Additional Security Controls
* **File Upload Controls:** Test upload forms with various file extensions, executable binaries, and oversized files. Check for restriction enforcement, storage location, and malware scanning.
* **Open Redirects:** Test parameters that take URLs or paths to ensure the application does not perform unvalidated redirects to untrusted external domains.
* **Logout Functionality:** Verify that logging out invalidates the session on the server side, preventing token reuse.
* **Rate Limiting:** Execute rapid, repeated requests against sensitive forms (login, password reset) to verify threshold enforcement and throttling mechanisms.
* **CSRF Protections:** Confirm state-changing operations incorporate unique, unpredictable anti-CSRF tokens or enforce `SameSite=Strict` cookie policies.
---

## Part 2: Step-by-Step Manual for Application Security Checks Using Burp Suite

### 1. Intercepting and Modifying Requests

* **Test Case 1.1: Intercept and modify GET requests**
  * **Steps:**
    1. Enable the **Intercept** feature in Burp Suite.
    2. Navigate to a page that uses GET requests.
    3. Capture the request and modify query parameters.
    4. Forward the modified request and observe the response.

* **Test Case 1.2: Intercept and modify POST requests**
  * **Steps:**
    1. Enable the **Intercept** feature in Burp Suite.
    2. Submit a form that uses POST requests.
    3. Capture the request and modify form data.
    4. Forward the modified request and observe the response.

---

### 2. Testing for SQL Injection

* **Test Case 2.1: Test login form for SQL injection**
  * **Steps:**
    1. Identify the login form.
    2. Inject payloads like `' OR 1=1 --` in the username and password fields.
    3. Observe if login is bypassed or if SQL errors are displayed.

* **Test Case 2.2: Test search functionality for SQL injection**
  * **Steps:**
    1. Identify the search input field.
    2. Inject payloads like `'; DROP TABLE users; --`.
    3. Observe if SQL errors are displayed or if the application behaves unexpectedly.

---

### 3. Cross-Site Scripting (XSS)

* **Test Case 3.1: Test reflected XSS in search input**
  * **Steps:**
    1. Identify the search input field.
    2. Inject payloads like `<script>alert('XSS')</script>`.
    3. Observe if the payload is executed in the browser.

* **Test Case 3.2: Test stored XSS in comment section**
  * **Steps:**
    1. Identify the comment input field.
    2. Inject payloads like `<script>alert('XSS')</script>`.
    3. Submit the comment and observe if the payload is executed when the comment is viewed.

---

### 4. Cross-Site Request Forgery (CSRF)

* **Test Case 4.1: Test form submission for CSRF**
  * **Steps:**
    1. Identify a form that changes state (e.g., updating user profile).
    2. Capture the request using Burp Suite.
    3. Create a CSRF PoC form and host it on a different domain.
    4. Test if the action can be performed without user interaction.

* **Test Case 4.2: Test AJAX requests for CSRF**
  * **Steps:**
    1. Identify AJAX requests that change state.
    2. Capture the request using Burp Suite.
    3. Create a CSRF PoC script to send the AJAX request.
    4. Test if the action can be performed without user interaction.

---

### 5. Testing for Authentication and Session Management Issues

* **Test Case 5.1: Test for weak password policies**
  * **Steps:**
    1. Attempt to create an account with weak passwords (e.g., `123456`, `password`).
    2. Observe if the application enforces strong password policies.

* **Test Case 5.2: Test for session fixation**
  * **Steps:**
    1. Capture the session token before login.
    2. Log in and observe if the session token remains the same.
    3. Test if the session token can be reused to hijack the session.

* **Test Case 5.3: Test for session expiration**
  * **Steps:**
    1. Log in and capture the session token.
    2. Wait for the session to expire (if applicable).
    3. Attempt to use the expired session token and observe if access is denied.

---

### 6. Directory Traversal

* **Test Case 6.1: Test file download functionality for directory traversal**
  * **Steps:**
    1. Identify file download functionality.
    2. Inject payloads like `../../etc/passwd` in the file path parameter.
    3. Observe if restricted files can be accessed.

* **Test Case 6.2: Test file upload functionality for directory traversal**
  * **Steps:**
    1. Identify file upload functionality.
    2. Upload a file with a payload in the filename (e.g., `../../etc/passwd`).
    3. Observe if the file is stored in an unintended directory.

---

### 7. File Upload Vulnerabilities

* **Test Case 7.1: Test for unrestricted file upload**
  * **Steps:**
    1. Identify file upload functionality.
    2. Attempt to upload files with various extensions (e.g., `.php`, `.jsp`).
    3. Observe if the application restricts file types.

* **Test Case 7.2: Test for executable file upload**
  * **Steps:**
    1. Identify file upload functionality.
    2. Upload a file with executable content (e.g., a PHP shell).
    3. Attempt to execute the uploaded file.

---

### 8. Information Disclosure

* **Test Case 8.1: Inspect HTTP responses for sensitive information**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Inspect headers and body for sensitive information (e.g., server versions, error messages).

* **Test Case 8.2: Test for verbose error messages**
  * **Steps:**
    1. Trigger errors in the application (e.g., invalid input).
    2. Observe if detailed error messages are displayed.

---

### 9. Testing for Insecure Direct Object References (IDOR)

* **Test Case 9.1: Test user profile access for IDOR**
  * **Steps:**
    1. Identify parameters that reference user profiles (e.g., user IDs).
    2. Modify the parameter value to access another user's profile.
    3. Observe if unauthorized access is granted.

* **Test Case 9.2: Test file access for IDOR**
  * **Steps:**
    1. Identify parameters that reference files (e.g., file IDs).
    2. Modify the parameter value to access another user's file.
    3. Observe if unauthorized access is granted.

---

### 10. Automated Scanning with Burp Suite

* **Test Case 10.1: Perform a comprehensive scan**
  * **Steps:**
    1. Configure the target scope in Burp Suite.
    2. Use the Burp Scanner to perform a comprehensive scan.
    3. Review the scan results and manually verify identified issues.

* **Test Case 10.2: Perform a targeted scan on specific functionality**
  * **Steps:**
    1. Identify specific functionality to test (e.g., login, file upload).
    2. Configure the target scope to include only the identified functionality.
    3. Use the Burp Scanner to perform a targeted scan.
    4. Review the scan results and manually verify identified issues.

---

### 11. Testing for Command Injection

* **Test Case 11.1: Test input fields for command injection**
  * **Steps:**
    1. Identify input fields that may be used in system commands (e.g., form fields, URL parameters).
    2. Inject payloads like `; ls -la` or `&& whoami`.
    3. Observe if the application executes the command and returns the output.

* **Test Case 11.2: Test file upload functionality for command injection**
  * **Steps:**
    1. Identify file upload functionality.
    2. Upload a file with a payload in the filename (e.g., `test; ls -la`).
    3. Observe if the application executes the command.

---

### 12. Testing for XML External Entity (XXE) Injection

* **Test Case 12.1: Test XML input for XXE injection**
  * **Steps:**
    1. Identify functionalities that accept XML input (e.g., file upload, API endpoints).
    2. Inject XXE payloads like:
       ```xml
       <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
       <foo>&xxe;</foo>
       ```
    3. Observe if the application processes the external entity and returns the content.

* **Test Case 12.2: Test SOAP requests for XXE injection**
  * **Steps:**
    1. Identify SOAP endpoints.
    2. Inject XXE payloads in the SOAP request body.
    3. Observe if the application processes the external entity and returns the content.

---

### 13. Testing for Server-Side Request Forgery (SSRF)

* **Test Case 13.1: Test URL input fields for SSRF**
  * **Steps:**
    1. Identify input fields that accept URLs (e.g., image URL upload).
    2. Inject internal network URLs (e.g., `http://localhost:8080`).
    3. Observe if the application makes a request to the internal URL.

* **Test Case 13.2: Test file upload functionality for SSRF**
  * **Steps:**
    1. Identify file upload functionality.
    2. Upload a file with a payload that includes an internal URL (e.g., `http://localhost:8080`).
    3. Observe if the application makes a request to the internal URL.

---

### 14. Testing for Open Redirects

* **Test Case 14.1: Test URL parameters for open redirects**
  * **Steps:**
    1. Identify URL parameters that accept URLs (e.g., `redirect` parameter).
    2. Inject external URLs (e.g., `http://malicious.com`).
    3. Observe if the application redirects to the external URL.

* **Test Case 14.2: Test form actions for open redirects**
  * **Steps:**
    1. Identify forms with action URLs.
    2. Modify the action URL to an external URL.
    3. Submit the form and observe if the application redirects to the external URL.

---

### 15. Testing for Business Logic Flaws

* **Test Case 15.1: Test for improper access control**
  * **Steps:**
    1. Identify functionalities that should be restricted (e.g., admin pages).
    2. Attempt to access the functionalities as a regular user.
    3. Observe if access is improperly granted.

* **Test Case 15.2: Test for improper workflow**
  * **Steps:**
    1. Identify multi-step processes (e.g., checkout process).
    2. Attempt to skip steps or perform steps out of order.
    3. Observe if the application handles the improper workflow correctly.

---

### 16. Testing for Security Misconfigurations

* **Test Case 16.1: Test for default credentials**
  * **Steps:**
    1. Identify login functionalities.
    2. Attempt to log in using common default credentials (e.g., `admin/admin`).
    3. Observe if access is granted.

* **Test Case 16.2: Test for unnecessary services**
  * **Steps:**
    1. Identify services running on the server (e.g., using Nmap).
    2. Check if unnecessary services are exposed.
    3. Attempt to interact with the unnecessary services.

---

### 17. Testing for Clickjacking

* **Test Case 17.1: Test for clickjacking vulnerability**
  * **Steps:**
    1. Create a malicious HTML page with an iframe pointing to the target application.
    2. Use CSS to make the iframe invisible or partially visible.
    3. Observe if the application can be interacted with through the iframe.

* **Test Case 17.2: Test for X-Frame-Options header**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check if the `X-Frame-Options` header is present and correctly configured.
    3. Observe if the application is protected against clickjacking.

---

### 18. Testing for Content Security Policy (CSP)

* **Test Case 18.1: Test for CSP header**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check if the `Content-Security-Policy` header is present and correctly configured.
    3. Observe if the application is protected against XSS and other attacks.

* **Test Case 18.2: Test for CSP bypass**
  * **Steps:**
    1. Identify CSP policies in place.
    2. Attempt to inject payloads that bypass the CSP (e.g., using inline scripts).
    3. Observe if the payload is executed.

---

### 19. Testing for Security Headers

* **Test Case 19.1: Test for HTTP Strict Transport Security (HSTS) header**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check if the `Strict-Transport-Security` header is present and correctly configured.
    3. Observe if the application enforces HTTPS.

* **Test Case 19.2: Test for X-Content-Type-Options header**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check if the `X-Content-Type-Options` header is present and correctly configured.
    3. Observe if the application prevents MIME type sniffing.

---

### 20. Testing for Rate Limiting and Brute Force Protection

* **Test Case 20.1: Test for rate limiting on login functionality**
  * **Steps:**
    1. Identify the login functionality.
    2. Use Burp Suite's Intruder tool to perform a brute force attack.
    3. Observe if the application implements rate limiting or account lockout mechanisms.

* **Test Case 20.2: Test for rate limiting on API endpoints**
  * **Steps:**
    1. Identify API endpoints.
    2. Use Burp Suite's Intruder tool to send a high volume of requests.
    3. Observe if the application implements rate limiting mechanisms.

---

### 21. Testing for JSON Web Token (JWT) Vulnerabilities

* **Test Case 21.1: Test for weak JWT signing key**
  * **Steps:**
    1. Capture JWT tokens used in the application.
    2. Attempt to brute force the signing key using tools like `jwt-cracker`.
    3. Observe if the signing key can be discovered.

* **Test Case 21.2: Test for JWT token tampering**
  * **Steps:**
    1. Capture JWT tokens used in the application.
    2. Modify the payload of the token (e.g., change user role).
    3. Re-sign the token with the discovered or guessed key.
    4. Observe if the application accepts the tampered token.

---

### 22. Testing for HTTP Parameter Pollution (HPP)

* **Test Case 22.1: Test for HPP in query parameters**
  * **Steps:**
    1. Identify functionalities that accept multiple query parameters.
    2. Inject duplicate parameters with different values (e.g., `param1=value1&param1=value2`).
    3. Observe if the application processes the parameters correctly.

* **Test Case 22.2: Test for HPP in POST data**
  * **Steps:**
    1. Identify functionalities that accept POST data.
    2. Inject duplicate parameters with different values in the POST body.
    3. Observe if the application processes the parameters correctly.

---

### 23. Testing for HTTP Host Header Injection

* **Test Case 23.1: Test for Host header injection in HTTP requests**
  * **Steps:**
    1. Capture HTTP requests using Burp Suite.
    2. Modify the `Host` header to an arbitrary value (e.g., `evil.com`).
    3. Observe if the application processes the modified Host header.

* **Test Case 23.2: Test for Host header injection in password reset functionality**
  * **Steps:**
    1. Identify password reset functionality.
    2. Capture the request and modify the `Host` header to an arbitrary value.
    3. Observe if the password reset link is sent to the modified Host.

---

### 24. Testing for Subdomain Takeover

* **Test Case 24.1: Test for subdomain takeover vulnerabilities**
  * **Steps:**
    1. Identify subdomains used by the application.
    2. Check if any subdomains are pointing to unclaimed resources (e.g., CNAME pointing to a non-existent S3 bucket).
    3. Attempt to claim the unclaimed resource and observe if the subdomain can be taken over.

* **Test Case 24.2: Test for dangling DNS records**
  * **Steps:**
    1. Identify DNS records for the application.
    2. Check if any DNS records are pointing to unclaimed resources.
    3. Attempt to claim the unclaimed resource and observe if the DNS record can be taken over.

---

### 25. Testing for Cache Poisoning

* **Test Case 25.1: Test for cache poisoning in HTTP responses**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Modify cache-related headers (e.g., `Cache-Control`, `Expires`).
    3. Observe if the modified response is cached by the application.

* **Test Case 25.2: Test for cache poisoning in web proxies**
  * **Steps:**
    1. Identify web proxies used by the application.
    2. Inject payloads in HTTP headers that may be cached by the proxy.
    3. Observe if the payload is cached and served to other users.

---

### 26. Testing for Cross-Origin Resource Sharing (CORS) Misconfigurations

* **Test Case 26.1: Test for permissive CORS policy**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check the `Access-Control-Allow-Origin` header for a wildcard (`*`) or arbitrary domains.
    3. Observe if the application allows cross-origin requests from untrusted domains.

* **Test Case 26.2: Test for CORS misconfigurations with credentials**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check the `Access-Control-Allow-Credentials` header.
    3. Observe if the application allows cross-origin requests with credentials from untrusted domains.

---

### 27. Testing for HTTP Response Splitting

* **Test Case 27.1: Test for HTTP response splitting in URL parameters**
  * **Steps:**
    1. Identify URL parameters that are reflected in HTTP headers.
    2. Inject payloads like `%0d%0aHeader: Value` in the parameters.
    3. Observe if the application processes the injected headers.

* **Test Case 27.2: Test for HTTP response splitting in POST data**
  * **Steps:**
    1. Identify functionalities that accept POST data.
    2. Inject payloads like `%0d%0aHeader: Value` in the POST body.
    3. Observe if the application processes the injected headers.

---

### 28. Testing for Insufficient Transport Layer Protection

* **Test Case 28.1: Test for mixed content issues**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check if the application loads resources (e.g., images, scripts) over HTTP on an HTTPS page.
    3. Observe if the application is vulnerable to mixed content issues.

* **Test Case 28.2: Test for weak SSL/TLS configurations**
  * **Steps:**
    1. Use tools like SSL Labs to analyze the SSL/TLS configuration of the application.
    2. Check for weak ciphers, protocols, and certificate issues.
    3. Observe if the application is vulnerable to SSL/TLS attacks.

---

### 29. Testing for Insufficient Logging and Monitoring

* **Test Case 29.1: Test for lack of logging on critical actions**
  * **Steps:**
    1. Perform critical actions (e.g., login, data modification) in the application.
    2. Check if the application logs these actions.
    3. Observe if the application lacks logging for critical actions.

* **Test Case 29.2: Test for insufficient monitoring of security events**
  * **Steps:**
    1. Perform security-related actions (e.g., multiple failed login attempts).
    2. Check if the application monitors and alerts on these actions.
    3. Observe if the application lacks monitoring for security events.

---

### 30. Testing for Business Logic Vulnerabilities

* **Test Case 30.1: Test for improper validation of discounts**
  * **Steps:**
    1. Identify functionalities that apply discounts (e.g., promo codes).
    2. Attempt to apply invalid or excessive discounts.
    3. Observe if the application improperly validates and applies the discounts.

* **Test Case 30.2: Test for improper validation of refunds**
  * **Steps:**
    1. Identify functionalities that process refunds.
    2. Attempt to request refunds for invalid or excessive amounts.
    3. Observe if the application improperly validates and processes the refunds.

---

### 31. Testing for HTTP Method Vulnerabilities

* **Test Case 31.1: Test for unsupported HTTP methods**
  * **Steps:**
    1. Identify endpoints in the application.
    2. Use Burp Suite to send requests with various HTTP methods (e.g., `PUT`, `DELETE`, `TRACE`).
    3. Observe if the application processes unsupported methods.

* **Test Case 31.2: Test for HTTP method override**
  * **Steps:**
    1. Identify endpoints that accept HTTP methods.
    2. Use Burp Suite to send requests with method override headers (e.g., `X-HTTP-Method-Override: DELETE`).
    3. Observe if the application processes the overridden method.

---

### 32. Testing for HTTP Header Injection

* **Test Case 32.1: Test for header injection in URL parameters**
  * **Steps:**
    1. Identify URL parameters that are reflected in HTTP headers.
    2. Inject payloads like `%0d%0aHeader: Value` in the parameters.
    3. Observe if the application processes the injected headers.

* **Test Case 32.2: Test for header injection in form fields**
  * **Steps:**
    1. Identify form fields that are reflected in HTTP headers.
    2. Inject payloads like `%0d%0aHeader: Value` in the form fields.
    3. Observe if the application processes the injected headers.

---

### 33. Testing for File Inclusion Vulnerabilities

* **Test Case 33.1: Test for Local File Inclusion (LFI)**
  * **Steps:**
    1. Identify input fields that accept file paths (e.g., URL parameters).
    2. Inject payloads like `../../../../etc/passwd`.
    3. Observe if the application includes and displays the contents of local files.

* **Test Case 33.2: Test for Remote File Inclusion (RFI)**
  * **Steps:**
    1. Identify input fields that accept file paths.
    2. Inject payloads with external URLs (e.g., `http://evil.com/shell.php`).
    3. Observe if the application includes and executes the remote file.

---

### 34. Testing for Path Traversal Vulnerabilities

* **Test Case 34.1: Test for path traversal in file download functionality**
  * **Steps:**
    1. Identify file download functionality.
    2. Inject payloads like `../../../../etc/passwd` in the file path parameter.
    3. Observe if the application allows access to restricted files.

* **Test Case 34.2: Test for path traversal in file upload functionality**
  * **Steps:**
    1. Identify file upload functionality.
    2. Upload a file with a payload in the filename (e.g., `../../../../etc/passwd`).
    3. Observe if the file is stored in an unintended directory.

---

### 35. Testing for Insecure Deserialization

* **Test Case 35.1: Test for insecure deserialization in JSON input**
  * **Steps:**
    1. Identify functionalities that accept JSON input.
    2. Inject malicious payloads in the JSON input (e.g., serialized objects).
    3. Observe if the application processes the deserialized objects insecurely.

* **Test Case 35.2: Test for insecure deserialization in serialized data**
  * **Steps:**
    1. Identify functionalities that accept serialized data (e.g., cookies, hidden fields).
    2. Inject malicious payloads in the serialized data.
    3. Observe if the application processes the deserialized objects insecurely.

---

### 36. Testing for Insufficient Authorization

* **Test Case 36.1: Test for horizontal privilege escalation**
  * **Steps:**
    1. Identify functionalities that should be restricted to specific users (e.g., user profiles).
    2. Attempt to access another user's functionality by modifying parameters (e.g., user ID).
    3. Observe if unauthorized access is granted.

* **Test Case 36.2: Test for vertical privilege escalation**
  * **Steps:**
    1. Identify functionalities that should be restricted to higher-privilege users (e.g., admin pages).
    2. Attempt to access the functionalities as a lower-privilege user.
    3. Observe if unauthorized access is granted.

---

### 37. Testing for Clickjacking (Advanced Checks)

* **Test Case 37.1: Test for clickjacking using an iframe**
  * **Steps:**
    1. Create a malicious HTML page with an iframe pointing to the target application.
    2. Use CSS to make the iframe invisible or partially visible.
    3. Observe if the application can be interacted with through the iframe.

* **Test Case 37.2: Test for X-Frame-Options header**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check if the `X-Frame-Options` header is present and correctly configured.
    3. Observe if the application is protected against clickjacking.

---

### 38. Testing for Security Misconfigurations

* **Test Case 38.1: Test for default credentials**
  * **Steps:**
    1. Identify login functionalities.
    2. Attempt to log in using common default credentials (e.g., `admin/admin`).
    3. Observe if access is granted.

* **Test Case 38.2: Test for unnecessary services**
  * **Steps:**
    1. Identify services running on the server (e.g., using Nmap).
    2. Check if unnecessary services are exposed.
    3. Attempt to interact with the unnecessary services.

---

### 39. Testing for Insufficient Transport Layer Protection

* **Test Case 39.1: Test for mixed content issues**
  * **Steps:**
    1. Capture HTTP responses using Burp Suite.
    2. Check if the application loads resources (e.g., images, scripts) over HTTP on an HTTPS page.
    3. Observe if the application is vulnerable to mixed content issues.

* **Test Case 39.2: Test for weak SSL/TLS configurations**
  * **Steps:**
    1. Use tools like SSL Labs to analyze the SSL/TLS configuration of the application.
    2. Check for weak ciphers, protocols, and certificate issues.
    3. Observe if the application is vulnerable to SSL/TLS attacks.

---

### 40. Testing for Insufficient Logging and Monitoring

* **Test Case 40.1: Test for lack of logging on critical actions**
  * **Steps:**
    1. Perform critical actions (e.g., login, data modification) in the application.
    2. Check if the application logs these actions.
    3. Observe if the application lacks logging for critical actions.

* **Test Case 40.2: Test for insufficient monitoring of security events**
  * **Steps:**
    1. Perform security-related actions (e.g., multiple failed login attempts).
    2. Check if the application monitors and alerts on these actions.
    3. Observe if the application lacks monitoring for security events.

---

### 41. Testing for Business Logic Vulnerabilities

* **Test Case 41.1: Test for improper validation of discounts**
  * **Steps:**
    1. Identify functionalities that apply discounts (e.g., promo codes).
    2. Attempt to apply invalid or excessive discounts.
    3. Observe if the application improperly validates and applies the discounts.

* **Test Case 41.2: Test for improper validation of refunds**
  * **Steps:**
    1. Identify functionalities that process refunds.
    2. Attempt to request refunds for invalid or excessive amounts.
    3. Observe if the application improperly validates and processes the refunds.

---

### 42. Testing for API Security

* **Test Case 42.1: Test for unauthenticated access to API endpoints**
  * **Steps:**
    1. Identify API endpoints.
    2. Attempt to access the endpoints without authentication.
    3. Observe if unauthorized access is granted.

* **Test Case 42.2: Test for improper rate limiting on API endpoints**
  * **Steps:**
    1. Identify API endpoints.
    2. Use Burp Suite's Intruder tool to send a high volume of requests.
    3. Observe if the application implements rate limiting mechanisms.

---

### 43. Testing for Mobile Application Security

* **Test Case 43.1: Test for insecure data storage**
  * **Steps:**
    1. Identify functionalities that store data on the device.
    2. Check if sensitive data is stored insecurely (e.g., unencrypted).
    3. Observe if the application is vulnerable to data theft.

* **Test Case 43.2: Test for insecure communication**
  * **Steps:**
    1. Capture network traffic between the mobile application and the server.
    2. Check if sensitive data is transmitted insecurely (e.g., unencrypted).
    3. Observe if the application is vulnerable to man-in-the-middle attacks.

---

### 44. Testing for HTTP/2 Vulnerabilities

* **Test Case 44.1: Test for HTTP/2 downgrading attacks**
  * **Steps:**
    1. Identify if the application supports HTTP/2.
    2. Attempt to downgrade the connection to HTTP/1.1.
    3. Observe if the application properly handles the downgrade.

* **Test Case 44.2: Test for HTTP/2-specific vulnerabilities**
  * **Steps:**
    1. Use tools like Burp Suite to send HTTP/2 requests.
    2. Inject payloads specific to HTTP/2 (e.g., header compression flaws/HPACK attacks).
    3. Observe response behavior and handling.

* **Test Case 45.1: Test for WebSocket handshake vulnerabilities**
  * **Steps:**
    1. Identify WebSocket connections in the application.
    2. Capture and modify the WebSocket handshake request.
    3. Observe if the application properly validates the handshake.

* **Test Case 45.2: Test for WebSocket message tampering**
  * **Steps:**
    1. Capture WebSocket messages using Burp Suite.
    2. Modify the messages and resend them.
    3. Observe if the application properly validates and processes the modified messages.

---

### 46. Testing for GraphQL Vulnerabilities

* **Test Case 46.1: Test for GraphQL introspection**
  * **Steps:**
    1. Identify GraphQL endpoints in the application.
    2. Send introspection queries to discover the schema.
    3. Observe if the application exposes sensitive information through introspection.

* **Test Case 46.2: Test for GraphQL injection**
  * **Steps:**
    1. Identify input fields that accept GraphQL queries.
    2. Inject malicious GraphQL queries (e.g., nested queries to cause denial of service).
    3. Observe if the application processes the malicious queries.

---

### 47. Testing for Server-Side Template Injection (SSTI)

* **Test Case 47.1: Test for SSTI in template rendering**
  * **Steps:**
    1. Identify input fields that are rendered using server-side templates.
    2. Inject template-specific payloads (e.g., `{{7*7}}` for Jinja2).
    3. Observe if the application executes the injected template code.

* **Test Case 47.2: Test for SSTI in email templates**
  * **Steps:**
    1. Identify functionalities that send emails using server-side templates.
    2. Inject template-specific payloads in the input fields.
    3. Observe if the application executes the injected template code in the email.

---

### 48. Testing for Business Logic Vulnerabilities

* **Test Case 48.1: Test for race conditions**
  * **Steps:**
    1. Identify functionalities that could be affected by race conditions (e.g., financial transactions).
    2. Use tools like Burp Suite's Intruder or Repeater (Turbo Intruder) to send multiple concurrent requests.
    3. Observe if the application properly handles concurrent requests.

* **Test Case 48.2: Test for improper validation of multi-step processes**
  * **Steps:**
    1. Identify multi-step processes (e.g., registration, checkout).
    2. Attempt to skip steps or perform steps out of order.
    3. Observe if the application properly validates the process flow.

---

### 49. Testing for OAuth/OpenID Connect Vulnerabilities

* **Test Case 49.1: Test for improper implementation of OAuth flows**
  * **Steps:**
    1. Identify OAuth flows used by the application (e.g., authorization code flow).
    2. Attempt to manipulate the flow (e.g., reuse authorization codes).
    3. Observe if the application properly validates the OAuth flow.

* **Test Case 49.2: Test for ID token manipulation in OpenID Connect**
  * **Steps:**
    1. Capture ID tokens used by the application.
    2. Modify the payload of the ID token (e.g., change user claims).
    3. Observe if the application properly validates the modified ID token.

---

### 50. Testing for Cloud-Specific Vulnerabilities

* **Test Case 50.1: Test for misconfigured cloud storage**
  * **Steps:**
    1. Identify cloud storage services used by the application (e.g., AWS S3).
    2. Check if the storage is publicly accessible.
    3. Attempt to access and modify the stored data.

* **Test Case 50.2: Test for insecure cloud API keys**
  * **Steps:**
    1. Identify cloud API keys used by the application.
    2. Check if the keys are exposed in the client-side code or configuration files.
    3. Attempt to use the exposed keys to access cloud services.

---

### 51. Testing for Dependency Vulnerabilities

* **Test Case 51.1: Test for outdated dependencies**
  * **Steps:**
    1. Identify dependencies used by the application (e.g., libraries, frameworks).
    2. Check if any dependencies are outdated or have known vulnerabilities.
    3. Observe if the application is vulnerable due to outdated dependencies.

* **Test Case 51.2: Test for vulnerable third-party components**
  * **Steps:**
    1. Identify third-party components used by the application (e.g., plugins, modules).
    2. Check if any components have known vulnerabilities.
    3. Observe if the application is vulnerable due to third-party components.

---

### 52. Testing for Cross-Site Script Inclusion (XSSI)

* **Test Case 52.1: Test for XSSI in JSON responses**
  * **Steps:**
    1. Identify endpoints that return JSON responses.
    2. Attempt to include the JSON response in a malicious script tag.
    3. Observe if the application is vulnerable to XSSI.

* **Test Case 52.2: Test for XSSI in script responses**
  * **Steps:**
    1. Identify endpoints that return script responses.
    2. Attempt to include the script response in a malicious script tag.
    3. Observe if the application is vulnerable to XSSI.

---

### 53. Testing for Content Spoofing

* **Test Case 53.1: Test for content spoofing in reflected input**
  * **Steps:**
    1. Identify input fields that reflect user input in the response.
    2. Inject payloads that modify the content (e.g., `<div>Fake Content</div>`).
    3. Observe if the application improperly reflects and displays the injected content.

* **Test Case 53.2: Test for content spoofing in URL parameters**
  * **Steps:**
    1. Identify URL parameters that are reflected in the response.
    2. Inject payloads that modify the content (e.g., `?message=<div>Fake Content</div>`).
    3. Observe if the application improperly reflects and displays the injected content.

---

### 54. Testing for HTTP Smuggling

* **Test Case 54.1: Test for HTTP request smuggling**
  * **Steps:**
    1. Identify endpoints that process HTTP requests.
    2. Inject payloads that exploit differences in HTTP request parsing (e.g., `Transfer-Encoding: chunked`).
    3. Observe if the application is vulnerable to HTTP request smuggling.

* **Test Case 54.2: Test for HTTP response smuggling**
  * **Steps:**
    1. Identify endpoints that process HTTP responses.
    2. Inject payloads that exploit differences in HTTP response parsing.
    3. Observe if the application is vulnerable to HTTP response smuggling.

---

### 55. Testing for CSRF Token Bypass

* **Test Case 55.1: Test for missing CSRF tokens**
  * **Steps:**
    1. Identify functionalities that should be protected by CSRF tokens (e.g., form submissions).
    2. Capture the request and remove the CSRF token.
    3. Observe if the application processes the request without the CSRF token.

* **Test Case 55.2: Test for predictable CSRF tokens**
  * **Steps:**
    1. Identify functionalities that use CSRF tokens.
    2. Capture multiple CSRF tokens and analyze their patterns.
    3. Attempt to predict and use a valid CSRF token.

---

### 56. Testing for DNS Rebinding

* **Test Case 56.1: Test for DNS rebinding vulnerabilities**
  * **Steps:**
    1. Identify endpoints that make DNS requests.
    2. Set up a DNS rebinding attack server.
    3. Observe if the application is vulnerable to DNS rebinding attacks.

* **Test Case 56.2: Test for DNS rebinding in web applications**
  * **Steps:**
    1. Identify functionalities that make DNS requests (e.g., URL fetch).
    2. Set up a DNS rebinding attack server.
    3. Observe if the application is vulnerable to DNS rebinding attacks.

---

### 57. Testing for User Enumeration

* **Test Case 57.1: Test for user enumeration in login functionality**
  * **Steps:**
    1. Identify the login functionality.
    2. Attempt to log in with valid and invalid usernames.
    3. Observe if the application provides different responses for valid and invalid usernames.

* **Test Case 57.2: Test for user enumeration in password reset functionality**
  * **Steps:**
    1. Identify the password reset functionality.
    2. Attempt to reset passwords for valid and invalid usernames.
    3. Observe if the application provides different responses for valid and invalid usernames.

---

### 58. Testing for HTTP Parameter Pollution (HPP)

* **Test Case 58.1: Test for HPP in query parameters**
  * **Steps:**
    1. Identify functionalities that accept multiple query parameters.
    2. Inject duplicate parameters with different values (e.g., `param1=value1&param1=value2`).
    3. Observe if the application processes the parameters correctly.

* **Test Case 58.2: Test for HPP in POST data**
  * **Steps:**
    1. Identify functionalities that accept POST data.
    2. Inject duplicate parameters with different values in the POST body.
    3. Observe if the application processes the parameters correctly.

---

### 59. Testing for HTTP Host Header Injection

* **Test Case 59.1: Test for Host header injection in HTTP requests**
  * **Steps:**
    1. Capture HTTP requests using Burp Suite.
    2. Modify the `Host` header to an arbitrary value (e.g., `evil.com`).
    3. Observe if the application processes the modified Host header.

* **Test Case 59.2: Test for Host header injection in password reset functionality**
  * **Steps:**
    1. Identify password reset functionality.
    2. Capture the request and modify the `Host` header to an arbitrary value.
    3. Observe if the password reset link is sent to the modified Host.

---

### 60. Testing for Subdomain Takeover

* **Test Case 60.1: Test for subdomain takeover vulnerabilities**
  * **Steps:**
    1. Identify subdomains used by the application.
    2. Check if any subdomains are pointing to unclaimed resources (e.g., CNAME pointing to a non-existent S3 bucket).
    3. Attempt to claim the unclaimed resource and observe if the subdomain can be taken over.

* **Test Case 60.2: Test for dangling DNS records**
  * **Steps:**
    1. Identify DNS records for the application.
    2. Check if any DNS records are pointing to unclaimed resources.
    3. Attempt to claim the unclaimed resource and observe if the DNS record can be taken over.