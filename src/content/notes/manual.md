---
title: "Manual Application Testing"
description: "Manual checklist for testing Web Applications."
pubDate: "Jul 14 2025"
heroImage: "/blog-placeholder-3.jpg"
---

# Sheet1

|Step-by-Step Manual for Application Security Checks Using Browser DeveloperTools|
|---|
| |
| |
|Tips for Documentation|
|For    each step, include screenshots and sample findings.|
|Document    both the process and the expected secure configuration.|
|Note    any deviations or vulnerabilities found.|
| |
|1. Checking HTTP Security Headers|
| |
|Steps:|
|1. Open    Developer Tools (F12 or Ctrl+Shift+I).|
|2. Go    to the Network tab.|
|3. Reload    the page to capture all network requests.|
|4. Click    on the main document request (usually the first entry).|
|5. In    the Headers section, review Response Headers for: |
|1. Content-Security-Policy|
|Content-Security-Policy:frame-ancestors 'none';|
|This prevents any domain from framing the content.This setting is recommended unless a specific need has been identified forframing.|
| |
|2. Strict-Transport-Security|
|https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html|
|HTTP Strict Transport Security (HSTS) is a web securitypolicy that ensures that browsers always use HTTPS to connect to websites. Partof its purpose is to remove the need to redirect users from HTTP to HTTPSwebsite versions or secure any such redirects.|
|3. X-Frame-Options|
|DENY, which prevents any domain fromframing the content. The "DENY" setting is recommended unless aspecific need has been identified for framing.|
| |
|4. X-Content-Type-Options|
|Content Security Policy (CSP) frame-ancestors directiveobsoletes X-Frame-Options for supporting browsers (source).|
|X-Frame-Options header is only useful when the HTTP responsewhere it is included has something to interact with (e.g. links, buttons). Ifthe HTTP response is a redirect or an API returning JSON data, X-Frame-Optionsdoes not provide any security.|
|Use Content Security Policy (CSP) frame-ancestors directiveif possible.|
|Do not allow displaying of the page in a frame.|
|X-Frame-Options: DENY|
| |
|5. Referrer-Policy|
|However,since not all users may be using the latest browserswe suggest forcing this behavior by sending this header on all responses.|
|Referrer-Policy: strict-origin-when-cross-origin|
| |
|6. Permissions-Policy|
|Set itand disable all the features that your site does not need or allow them only tothe authorized domains:|
|Permissions-Policy: geolocation=(),camera=(), microphone=()|
| |
|7. Access-Control-Allow-Origin     (for CORS)|
|8. Check     banner information such as ASP.NET version, IIS server version|
|9. X-Powered-By     Header is NOT Present|
|Check to ensure that X-Powered-By Header is NOT Present inHeader response|
| |
|6. Note    missing or misconfigured headers.|
|2. Cookie Security Attributes|
| |
|Steps:|
|1. In    the Network tab, select a request and check the Response Headers    for Set-Cookie.|
|2. Alternatively,    go to the Application (or Storage) tab.|
|3. Select    Cookies under the Storage section.|
|4. For    each cookie, check: |
|10. Secure     (should be set for HTTPS)|
|11. HttpOnly (should be set for session/auth cookies)|
|12. SameSite (Strict or Lax preferred for most cookies)|
|5. Note    cookies missing these attributes.|
|3. HTTPS and Mixed Content|
| |
|Steps:|
|1. In    the browser address bar, ensure the URL starts with https://.|
|2. In    the Console tab, look for mixed content warnings.|
|3. In    the Network tab, filter by http and check if any requests are made    over HTTP.|
|4. Note    any insecure requests or resources.|
|4. Source Code Exposure (Source Maps, Sensitive Data)|
| |
|Steps:|
|1. In    the Network tab, filter by .js or .map.|
|2. Check    if source map files (.map) are accessible (open them in a new tab).|
|3. In    the Sources tab, review JavaScript files for: |
|13. Hardcoded     secrets, API keys, credentials.|
|14. Comments     revealing sensitive information.|
|4. Note    any exposed sensitive information.|
|5. DOM and Client-Side Validation|
| |
|Steps:|
|1. Go    to the Elements tab and inspect input fields and forms.|
|2. Check    for HTML5 validation attributes (e.g., required, pattern, maxlength).|
|3. Try    submitting forms with invalid data and observe responses.|
|4. In    the Console tab, look for JavaScript validation scripts.|
|5. Note    missing or weak client-side validation.|
|6. DOM-based XSS Checks|
| |
|Steps:|
|1. In    the Elements and Sources tabs, look for: |
|15. Inline     event handlers (e.g., onclick, onerror).|
|16. Usage     of innerHTML, document.write, or similar functions.|
|2. Try    injecting harmless scripts (e.g., <img src=x onerror=alert(1)>) into input fields or URL parameters.|
|3. Observe    if the input is reflected in the DOM without sanitization.|
|4. Note    any successful script execution.|
|7. Session Management|
| |
|Steps:|
|1. In    the Application/Storage tab, review cookies and session storage.|
|2. Ensure    session tokens are not stored in local storage or exposed in URLs.|
|3. Check    for session expiration by leaving the session idle and observing behavior.|
|4. Attempt    to reuse session tokens after logout.|
|5. Note    insecure session handling.|
|8. API Endpoints and Sensitive Data Exposure|
| |
|Steps:|
|1. In    the Network tab, filter by XHR or Fetch.|
|2. Review    API requests and responses for: |
|17. Sensitive     data (PII, passwords, tokens) in responses.|
|18. Sensitive     data sent in URLs (should use POST body).|
|3. Check    for unnecessary data exposure in API responses.|
|4. Note    any sensitive data leaks.|
|9. CORS Policy|
| |
|Steps:|
|1. In    the Network tab, select API requests.|
|2. In Response    Headers, check for Access-Control-Allow-Origin and related headers.|
|3. Ensure    only trusted origins are allowed.|
|4. Note    overly permissive CORS settings (e.g., *).|
|10. Error Handling and Information Disclosure|
| |
|Steps:|
|1. Submit    invalid or unexpected input to forms and APIs.|
|2. In    the Network tab, review error responses.|
|3. In    the Console tab, look for error messages.|
|4. Note    if error messages reveal stack traces, file paths, or internal logic.|
|11. Third-Party Scripts and Resources|
| |
|Steps:|
|1. In    the Network tab, filter by JS or Script.|
|2. Review    the source of all loaded scripts.|
|3. In    the Elements tab, check for <script> tags referencing    external domains.|
|4. Note    use of untrusted or unnecessary third-party scripts.|
|12. Local Storage, Session Storage, and IndexedDB|
| |
|Steps:|
|1. In    the Application/Storage tab, review: |
|19. Local     Storage|
|20. Session     Storage|
|21. IndexedDB|
|2. Look    for sensitive data (tokens, PII) stored in these locations.|
|3. Note    any sensitive data found.|
|13. Autocomplete and Password Field Security|
| |
|Steps:|
|1. In    the Elements tab, inspect input fields for: |
|22. autocomplete="off"     on sensitive fields (e.g., passwords).|
|23. type="password"     for password fields.|
|2. Note    missing or misconfigured attributes.|
|14. Cache Control|
| |
|Steps:|
|1. In    the Network tab, review Response Headers for: |
|24. Cache-Control|
|25. Pragma|
|26. Expires|
|2. Ensure    sensitive pages have headers to prevent caching.|
|3. Note    missing or weak cache control headers.|
|15. Clickjacking Protections|
| |
|Steps:|
|1. In    the Network tab, check for X-Frame-Options or    Content-Security-Policy: frame-ancestors.|
|1.X-Frame-Options: DENY|
| |
|        Purpose: Prevents thepage from being displayed in a frame, iframe, orobject.|
|        Effect: No site(including your own) can embed this page in an iframe.|
|        Security Benefit: Strong protection against clickjacking.|
|2.Content-Security-Policy: frame-ancestors 'none'|
| |
|        Purpose: Part of theContent Security Policy (CSP) header, it controls which origins can embed thepage in a frame or iframe.|
|        Effect: 'none' means noorigin is allowed to embed the page.|
|        Security Benefit: This is the most restrictive setting and offers robust defense againstclickjacking.|
| |
|2. Note    missing or misconfigured headers.|
|Additional Parameters to Check|
|File    Upload Security: Try uploading files and observe restrictions (file    type, size, scanning).|
|Redirects:    Check for open redirects by manipulating URL parameters.|
|Logout    Functionality: Ensure logout invalidates session tokens.|
|Rate    Limiting: Attempt repeated actions and observe if rate limiting is    enforced.|
|CSRF    Protections: Check for anti-CSRF tokens in forms and API requests.|
| |
|Step-by-Step Manual for Application Security Checks Using BurpSuite|
| |
|1. Interceptingand Modifying Requests|
| |
|        Test Case 1.1: Intercept and modify GET requests |
|o   Steps: |
|  Enable the Intercept feature in Burp Suite.|
|  Navigate to a page that uses GET requests.|
|  Capture the request and modify queryparameters.|
|  Forward the modified request and observe theresponse.|
|https://d10dc6brwriiq0.cloudfront.net|
| |
|        Test Case 1.2: Intercept and modify POST requests |
|o   Steps: |
|  Enable the Intercept feature in Burp Suite.|
|  Submit a form that uses POST requests.|
|  Capture the request and modify form data.|
|  Forward the modified request and observe theresponse.|
|2. Testing forSQL Injection|
| |
|        Test Case 2.1: Test login form for SQL injection |
|o   Steps: |
|  Identify the login form.|
|  Inject payloads like ' OR 1=1 -- in the username and password fields.|
|  Observe if login is bypassed or if SQL errorsare displayed.|
|        Test Case 2.2: Test search functionality for SQL injection |
|o   Steps: |
|  Identify the search input field.|
|  Inject payloads like '; DROP TABLE users; --.|
|  Observe if SQL errors are displayed or if theapplication behaves unexpectedly.|
|3. Cross-SiteScripting (XSS)|
| |
|        Test Case 3.1: Test reflected XSS in search input |
|o   Steps: |
|  Identify the search input field.|
|  Inject payloads like <script>alert('XSS')</script>.|
|  Observe if the payload is executed in thebrowser.|
|        Test Case 3.2: Test stored XSS in comment section |
|o   Steps: |
|  Identify the comment input field.|
|  Inject payloads like <script>alert('XSS')</script>.|
|  Submit the comment and observe if the payloadis executed when the comment is viewed.|
|4. Cross-SiteRequest Forgery (CSRF)|
| |
|        Test Case 4.1: Test form submission for CSRF |
|o   Steps: |
|  Identify a form that changes state (e.g.,updating user profile).|
|  Capture the request using Burp Suite.|
|  Create a CSRF PoC form and host it on adifferent domain.|
|  Test if the action can be performed withoutuser interaction.|
|        Test Case 4.2: Test AJAX requests for CSRF |
|o   Steps: |
|  Identify AJAX requests that change state.|
|  Capture the request using Burp Suite.|
|  Create a CSRF PoC script to send the AJAXrequest.|
|  Test if the action can be performed withoutuser interaction.|
|5. Testing forAuthentication and Session Management Issues|
| |
|        Test Case 5.1: Test for weak password policies |
|o   Steps: |
|  Attempt to create an account with weakpasswords (e.g., 123456, password).|
|  Observe if the application enforces strongpassword policies.|
|        Test Case 5.2: Test for session fixation |
|o   Steps: |
|  Capture the session token before login.|
|  Log in and observe if the session tokenremains the same.|
|  Test if the session token can be reused tohijack the session.|
|        Test Case 5.3: Test for session expiration |
|o   Steps: |
|  Log in and capture the session token.|
|  Wait for the session to expire (ifapplicable).|
|  Attempt to use the expired session token andobserve if access is denied.|
|6. DirectoryTraversal|
| |
|        Test Case 6.1: Test file download functionality for directory traversal |
|o   Steps: |
|  Identify file download functionality.|
|  Inject payloads like ../../etc/passwd in the file path parameter.|
|  Observe if restricted files can be accessed.|
|        Test Case 6.2: Test file upload functionality for directory traversal |
|o   Steps: |
|  Identify file upload functionality.|
|  Upload a file with a payload in the filename(e.g., ../../etc/passwd).|
|  Observe if the file is stored in anunintended directory.|
|7. File UploadVulnerabilities|
| |
|        Test Case 7.1: Test for unrestricted file upload |
|o   Steps: |
|  Identify file upload functionality.|
|  Attempt to upload files with variousextensions (e.g., .php, .jsp).|
|  Observe if the application restricts filetypes.|
|        Test Case 7.2: Test for executable file upload |
|o   Steps: |
|  Identify file upload functionality.|
|  Upload a file with executable content (e.g.,a PHP shell).|
|  Attempt to execute the uploaded file.|
|8. InformationDisclosure|
| |
|        Test Case 8.1: Inspect HTTP responses for sensitive information|
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Inspect headers and body for sensitiveinformation (e.g., server versions, error messages).|
|        Test Case 8.2: Test for verbose error messages |
|o   Steps: |
|  Trigger errors in the application (e.g.,invalid input).|
|  Observe if detailed error messages aredisplayed.|
|9. Testing forInsecure Direct Object References (IDOR)|
| |
|        Test Case 9.1: Test user profile access for IDOR |
|o   Steps: |
|  Identify parameters that reference userprofiles (e.g., user IDs).|
|  Modify the parameter value to access anotheruser's profile.|
|  Observe if unauthorized access is granted.|
|        Test Case 9.2: Test file access for IDOR |
|o   Steps: |
|  Identify parameters that reference files(e.g., file IDs).|
|  Modify the parameter value to access anotheruser's file.|
|  Observe if unauthorized access is granted.|
|10. AutomatedScanning with Burp Suite|
| |
|        Test Case 10.1: Perform a comprehensive scan |
|o   Steps: |
|  Configure the target scope in Burp Suite.|
|  Use the Burp Scanner to perform acomprehensive scan.|
|  Review the scan results and manually verifyidentified issues.|
|        Test Case 10.2: Perform a targeted scan on specific functionality|
|o   Steps: |
|  Identify specific functionality to test(e.g., login, file upload).|
|  Configure the target scope to include onlythe identified functionality.|
|  Use the Burp Scanner to perform a targetedscan.|
|  Review the scan results and manually verifyidentified issues.|
|11. Testing forCommand Injection|
| |
|        Test Case 11.1: Test input fields for command injection |
|o   Steps: |
|  Identify input fields that may be used insystem commands (e.g., form fields, URL parameters).|
|  Inject payloads like ; ls -la or && whoami.|
|  Observe if the application executes thecommand and returns the output.|
|        Test Case 11.2: Test file upload functionality for command injection |
|o   Steps: |
|  Identify file upload functionality.|
|  Upload a file with a payload in the filename(e.g., test; ls -la).|
|  Observe if the application executes thecommand.|
|12. Testing forXML External Entity (XXE) Injection|
| |
|        Test Case 12.1: Test XML input for XXE injection |
|o   Steps: |
|  Identify functionalities that accept XMLinput (e.g., file upload, API endpoints).|
|  Inject XXE payloads like:|
|HTML, XML|
|<!DOCTYPEfoo [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>|
|<foo>&xxe;</foo>|
| |
| |
|  Observe if the application processes theexternal entity and returns the content.|
|        Test Case 12.2: Test SOAP requests for XXE injection |
|o   Steps: |
|  Identify SOAP endpoints.|
|  Inject XXE payloads in the SOAP request body.|
|  Observe if the application processes theexternal entity and returns the content.|
|13. Testing forServer-Side Request Forgery (SSRF)|
| |
|        Test Case 13.1: Test URL input fields for SSRF |
|o   Steps: |
|  Identify input fields that accept URLs (e.g.,image URL upload).|
|  Inject internal network URLs (e.g., http://localhost:8080).|
|  Observe if the application makes a request tothe internal URL.|
|        Test Case 13.2: Test file upload functionality for SSRF |
|o   Steps: |
|  Identify file upload functionality.|
|  Upload a file with a payload that includes aninternal URL (e.g., http://localhost:8080).|
|  Observe if the application makes a request tothe internal URL.|
|14. Testing forOpen Redirects|
| |
|        Test Case 14.1: Test URL parameters for open redirects |
|o   Steps: |
|  Identify URL parameters that accept URLs(e.g., redirect parameter).|
|  Inject external URLs (e.g., http://malicious.com).|
|  Observe if the application redirects to theexternal URL.|
|        Test Case 14.2: Test form actions for open redirects |
|o   Steps: |
|  Identify forms with action URLs.|
|  Modify the action URL to an external URL.|
|  Submit the form and observe if theapplication redirects to the external URL.|
|15. Testing forBusiness Logic Flaws|
| |
|        Test Case 15.1: Test for improper access control |
|o   Steps: |
|  Identify functionalities that should berestricted (e.g., admin pages).|
|  Attempt to access the functionalities as aregular user.|
|  Observe if access is improperly granted.|
|        Test Case 15.2: Test for improper workflow |
|o   Steps: |
|  Identify multi-step processes (e.g., checkoutprocess).|
|  Attempt to skip steps or perform steps out oforder.|
|  Observe if the application handles theimproper workflow correctly.|
|16. Testing forSecurity Misconfigurations|
| |
|        Test Case 16.1: Test for default credentials |
|o   Steps: |
|  Identify login functionalities.|
|  Attempt to log in using common defaultcredentials (e.g., admin/admin).|
|  Observe if access is granted.|
|        Test Case 16.2: Test for unnecessary services |
|o   Steps: |
|  Identify services running on the server(e.g., using nmap).|
|  Check if unnecessary services are exposed.|
|  Attempt to interact with the unnecessaryservices.|
|17. Testing forClickjacking|
| |
|        Test Case 17.1: Test for clickjacking vulnerability |
|o   Steps: |
|  Create a malicious HTML page with an iframe pointing to the target application.|
|  Use CSS to make the iframeinvisible or partially visible.|
|  Observe if the application can be interactedwith through the iframe.|
|        Test Case 17.2: Test for X-Frame-Options header |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check if the X-Frame-Options header is present and correctly configured.|
|  Observe if the application is protectedagainst clickjacking.|
|18. Testing forContent Security Policy (CSP)|
| |
|        Test Case 18.1: Test for CSP header |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check if the Content-Security-Policy header is present and correctly configured.|
|  Observe if the application is protectedagainst XSS and other attacks.|
|        Test Case 18.2: Test for CSP bypass |
|o   Steps: |
|  Identify CSP policies in place.|
|  Attempt to inject payloads that bypass theCSP (e.g., using inline scripts).|
|  Observe if the payload is executed.|
|19. Testing forSecurity Headers|
| |
|        Test Case 19.1: Test for HTTP Strict Transport Security (HSTS) header |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check if the Strict-Transport-Security header is present and correctly configured.|
|  Observe if the application enforces HTTPS.|
|        Test Case 19.2: Test for X-Content-Type-Options header |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check if the X-Content-Type-Options header is present and correctly configured.|
|  Observe if the application prevents MIME typesniffing.|
|20. Testing forRate Limiting and Brute Force Protection|
| |
|        Test Case 20.1: Test for rate limiting on login functionality |
|o   Steps: |
|  Identify the login functionality.|
|  Use Burp Suite's Intruder tool to perform abrute force attack.|
|  Observe if the application implements ratelimiting or account lockout mechanisms.|
|        Test Case 20.2: Test for rate limiting on API endpoints |
|o   Steps: |
|  Identify API endpoints.|
|  Use Burp Suite's Intruder tool to send a highvolume of requests.|
|  Observe if the application implements ratelimiting mechanisms.|
|21. Testing forJSON Web Token (JWT) Vulnerabilities|
| |
|        Test Case 21.1: Test for weak JWT signing key |
|o   Steps: |
|  Capture JWT tokens used in the application.|
|  Attempt to brute force the signing key usingtools like jwt-cracker.|
|  Observe if the signing key can be discovered.|
|        Test Case 21.2: Test for JWT token tampering |
|o   Steps: |
|  Capture JWT tokens used in the application.|
|  Modify the payload of the token (e.g., changeuser role).|
|  Re-sign the token with the discovered orguessed key.|
|  Observe if the application accepts thetampered token.|
|22. Testing forHTTP Parameter Pollution (HPP)|
| |
|        Test Case 22.1: Test for HPP in query parameters |
|o   Steps: |
|  Identify functionalities that accept multiplequery parameters.|
|  Inject duplicate parameters with differentvalues (e.g., param1=value1&param1=value2).|
|  Observe if the application processes theparameters correctly.|
|        Test Case 22.2: Test for HPP in POST data |
|o   Steps: |
|  Identify functionalities that accept POSTdata.|
|  Inject duplicate parameters with differentvalues in the POST body.|
|  Observe if the application processes theparameters correctly.|
|23. Testing forHTTP Host Header Injection|
| |
|        Test Case 23.1: Test for Host header injection in HTTP requests |
|o   Steps: |
|  Capture HTTP requests using Burp Suite.|
|  Modify the Host header to an arbitrary value(e.g., evil.com).|
|  Observe if the application processes themodified Host header.|
|        Test Case 23.2: Test for Host header injection in password reset functionality|
|o   Steps: |
|  Identify password reset functionality.|
|  Capture the request and modify the Hostheader to an arbitrary value.|
|  Observe if the password reset link is sent tothe modified Host.|
|24. Testing forSubdomain Takeover|
| |
|        Test Case 24.1: Test for subdomain takeover vulnerabilities |
|o   Steps: |
|  Identify subdomains used by the application.|
|  Check if any subdomains are pointing tounclaimed resources (e.g., CNAME pointing to a non-existent S3 bucket).|
|  Attempt to claim the unclaimed resource andobserve if the subdomain can be taken over.|
|        Test Case 24.2: Test for dangling DNS records |
|o   Steps: |
|  Identify DNS records for the application.|
|  Check if any DNS records are pointing tounclaimed resources.|
|  Attempt to claim the unclaimed resource andobserve if the DNS record can be taken over.|
|25. Testing forCache Poisoning|
| |
|        Test Case 25.1: Test for cache poisoning in HTTP responses |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Modify cache-related headers (e.g., Cache-Control, Expires).|
|  Observe if the modified response is cached bythe application.|
|        Test Case 25.2: Test for cache poisoning in web proxies |
|o   Steps: |
|  Identify web proxies used by the application.|
|  Inject payloads in HTTP headers that may becached by the proxy.|
|  Observe if the payload is cached and servedto other users.|
|26. Testing forCross-Origin Resource Sharing (CORS) Misconfigurations|
| |
|        Test Case 26.1: Test for permissive CORS policy |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check the Access-Control-Allow-Origin header for a wildcard (*) or arbitrarydomains.|
|  Observe if the application allowscross-origin requests from untrusted domains.|
|        Test Case 26.2: Test for CORS misconfigurations with credentials |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check the Access-Control-Allow-Credentials header.|
|  Observe if the application allowscross-origin requests with credentials from untrusted domains.|
|27. Testing forHTTP Response Splitting|
| |
|        Test Case 27.1: Test for HTTP response splitting in URL parameters|
|o   Steps: |
|  Identify URL parameters that are reflected inHTTP headers.|
|  Inject payloads like %0d%0aHeader: Value in the parameters.|
|  Observe if the application processes theinjected headers.|
|        Test Case 27.2: Test for HTTP response splitting in POST data |
|o   Steps: |
|  Identify functionalities that accept POSTdata.|
|  Inject payloads like %0d%0aHeader: Value in the POST body.|
|  Observe if the application processes the injectedheaders.|
|28. Testing forInsufficient Transport Layer Protection|
| |
|        Test Case 28.1: Test for mixed content issues |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check if the application loads resources(e.g., images, scripts) over HTTP on an HTTPS page.|
|  Observe if the application is vulnerable tomixed content issues.|
|        Test Case 28.2: Test for weak SSL/TLS configurations |
|o   Steps: |
|  Use tools like SSL Labs to analyze theSSL/TLS configuration of the application.|
|  Check for weak ciphers, protocols, andcertificate issues.|
|  Observe if the application is vulnerable toSSL/TLS attacks.|
|29. Testing forInsufficient Logging and Monitoring|
| |
|        Test Case 29.1: Test for lack of logging on critical actions |
|o   Steps: |
|  Perform critical actions (e.g., login, datamodification) in the application.|
|  Check if the application logs these actions.|
|  Observe if the application lacks logging forcritical actions.|
|        Test Case 29.2: Test for insufficient monitoring of security events |
|o   Steps: |
|  Perform security-related actions (e.g.,multiple failed login attempts).|
|  Check if the application monitors and alertson these actions.|
|  Observe if the application lacks monitoringfor security events.|
|30. Testing forBusiness Logic Vulnerabilities|
| |
|        Test Case 30.1: Test for improper validation of discounts |
|o   Steps: |
|  Identify functionalities that apply discounts(e.g., promo codes).|
|  Attempt to apply invalid or excessivediscounts.|
|  Observe if the application improperlyvalidates and applies the discounts.|
|        Test Case 30.2: Test for improper validation of refunds |
|o   Steps: |
|  Identify functionalities that processrefunds.|
|  Attempt to request refunds for invalid orexcessive amounts.|
|  Observe if the application improperlyvalidates and processes the refunds.|
|31. Testing forHTTP Method Vulnerabilities|
| |
|        Test Case 31.1: Test for unsupported HTTP methods |
|o   Steps: |
|  Identify endpoints in the application.|
|  Use Burp Suite to send requests with variousHTTP methods (e.g., PUT, DELETE, TRACE).|
|  Observe if the application processes unsupportedmethods.|
|        Test Case 31.2: Test for HTTP method override |
|o   Steps: |
|  Identify endpoints that accept HTTP methods.|
|  Use Burp Suite to send requests with methodoverride headers (e.g., X-HTTP-Method-Override: DELETE).|
|  Observe if the application processes theoverridden method.|
|32. Testing forHTTP Header Injection|
| |
|        Test Case 32.1: Test for header injection in URL parameters |
|o   Steps: |
|  Identify URL parameters that are reflected inHTTP headers.|
|  Inject payloads like %0d%0aHeader: Value in the parameters.|
|  Observe if the application processes theinjected headers.|
|        Test Case 32.2: Test for header injection in form fields |
|o   Steps: |
|  Identify form fields that are reflected inHTTP headers.|
|  Inject payloads like %0d%0aHeader: Value in the form fields.|
|  Observe if the application processes theinjected headers.|
|33. Testing forFile Inclusion Vulnerabilities|
| |
|        Test Case 33.1: Test for Local File Inclusion (LFI) |
|o   Steps: |
|  Identify input fields that accept file paths(e.g., URL parameters).|
|  Inject payloads like ../../../../etc/passwd.|
|  Observe if the application includes anddisplays the contents of local files.|
|        Test Case 33.2: Test for Remote File Inclusion (RFI) |
|o   Steps: |
|  Identify input fields that accept file paths.|
|  Inject payloads with external URLs (e.g., http://evil.com/shell.php).|
|  Observe if the application includes andexecutes the remote file.|
|34. Testing forPath Traversal Vulnerabilities|
| |
|        Test Case 34.1: Test for path traversal in file download functionality |
|o   Steps: |
|  Identify file download functionality.|
|  Inject payloads like ../../../../etc/passwd in the file path parameter.|
|  Observe if the application allows access torestricted files.|
|        Test Case 34.2: Test for path traversal in file upload functionality |
|o   Steps: |
|  Identify file upload functionality.|
|  Upload a file with a payload in the filename(e.g., ../../../../etc/passwd).|
|  Observe if the file is stored in anunintended directory.|
|35. Testing forInsecure Deserialization|
| |
|        Test Case 35.1: Test for insecure deserialization in JSON input |
|o   Steps: |
|  Identify functionalities that accept JSONinput.|
|  Inject malicious payloads in the JSON input(e.g., serialized objects).|
|  Observe if the application processes thedeserialized objects insecurely.|
|        Test Case 35.2: Test for insecure deserialization in serialized data |
|o   Steps: |
|  Identify functionalities that acceptserialized data (e.g., cookies, hidden fields).|
|  Inject malicious payloads in the serializeddata.|
|  Observe if the application processes thedeserialized objects insecurely.|
|36. Testing forInsufficient Authorization|
| |
|        Test Case 36.1: Test for horizontal privilege escalation |
|o   Steps: |
|  Identify functionalities that should berestricted to specific users (e.g., user profiles).|
|  Attempt to access another user'sfunctionality by modifying parameters (e.g., user ID).|
|  Observe if unauthorized access is granted.|
|        Test Case 36.2: Test for vertical privilege escalation |
|o   Steps: |
|  Identify functionalities that should berestricted to higher-privilege users (e.g., admin pages).|
|  Attempt to access the functionalities as alower-privilege user.|
|  Observe if unauthorized access is granted.|
|37. Testing forClickjacking|
| |
|        Test Case 37.1: Test for clickjacking using an iframe|
|o   Steps: |
|  Create a malicious HTML page with an iframe pointing to the target application.|
|  Use CSS to make the iframeinvisible or partially visible.|
|  Observe if the application can be interactedwith through the iframe.|
|        Test Case 37.2: Test for X-Frame-Options header |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check if the X-Frame-Options header is present and correctly configured.|
|  Observe if the application is protectedagainst clickjacking.|
|38. Testing forSecurity Misconfigurations|
| |
|        Test Case 38.1: Test for default credentials |
|o   Steps: |
|  Identify login functionalities.|
|  Attempt to log in using common defaultcredentials (e.g., admin/admin).|
|  Observe if access is granted.|
|        Test Case 38.2: Test for unnecessary services |
|o   Steps: |
|  Identify services running on the server(e.g., using nmap).|
|  Check if unnecessary services are exposed.|
|  Attempt to interact with the unnecessaryservices.|
|39. Testing forInsufficient Transport Layer Protection|
| |
|        Test Case 39.1: Test for mixed content issues |
|o   Steps: |
|  Capture HTTP responses using Burp Suite.|
|  Check if the application loads resources(e.g., images, scripts) over HTTP on an HTTPS page.|
|  Observe if the application is vulnerable tomixed content issues.|
|        Test Case 39.2: Test for weak SSL/TLS configurations |
|o   Steps: |
|  Use tools like SSL Labs to analyze theSSL/TLS configuration of the application.|
|  Check for weak ciphers, protocols, andcertificate issues.|
|  Observe if the application is vulnerable toSSL/TLS attacks.|
|40. Testing forInsufficient Logging and Monitoring|
| |
|        Test Case 40.1: Test for lack of logging on critical actions |
|o   Steps: |
|  Perform critical actions (e.g., login, datamodification) in the application.|
|  Check if the application logs these actions.|
|  Observe if the application lacks logging forcritical actions.|
|        Test Case 40.2: Test for insufficient monitoring of security events |
|o   Steps: |
|  Perform security-related actions (e.g.,multiple failed login attempts).|
|  Check if the application monitors and alertson these actions.|
|  Observe if the application lacks monitoringfor security events.|
|41. Testing forBusiness Logic Vulnerabilities|
| |
|        Test Case 41.1: Test for improper validation of discounts |
|o   Steps: |
|  Identify functionalities that apply discounts(e.g., promo codes).|
|  Attempt to apply invalid or excessivediscounts.|
|  Observe if the application improperlyvalidates and applies the discounts.|
|        Test Case 41.2: Test for improper validation of refunds |
|o   Steps: |
|  Identify functionalities that processrefunds.|
|  Attempt to request refunds for invalid orexcessive amounts.|
|  Observe if the application improperlyvalidates and processes the refunds.|
|42. Testing forAPI Security|
| |
|        Test Case 42.1: Test for unauthenticated access to API endpoints |
|o   Steps: |
|  Identify API endpoints.|
|  Attempt to access the endpoints withoutauthentication.|
|  Observe if unauthorized access is granted.|
|        Test Case 42.2: Test for improper rate limiting on API endpoints|
|o   Steps: |
|  Identify API endpoints.|
|  Use Burp Suite's Intruder tool to send a highvolume of requests.|
|  Observe if the application implements ratelimiting mechanisms.|
|43. Testing forMobile Application Security|
| |
|        Test Case 43.1: Test for insecure data storage |
|o   Steps: |
|  Identify functionalities that store data onthe device.|
|  Check if sensitive data is stored insecurely(e.g., unencrypted).|
|  Observe if the application is vulnerable todata theft.|
|        Test Case 43.2: Test for insecure communication |
|o   Steps: |
|  Capture network traffic between the mobileapplication and the server.|
|  Check if sensitive data is transmittedinsecurely (e.g., unencrypted).|
|  Observe if the application is vulnerable toman-in-the-middle attacks.|
|44. Testing forHTTP/2 Vulnerabilities|
| |
|        Test Case 44.1: Test for HTTP/2 downgrading attacks |
|o   Steps: |
|  Identify if the application supports HTTP/2.|
|  Attempt to downgrade the connection toHTTP/1.1.|
|  Observe if the application properly handlesthe downgrade.|
|        Test Case 44.2: Test for HTTP/2-specific vulnerabilities |
|o   Steps: |
|  Use tools like Burp Suite to send HTTP/2requests.|
|  Inject payloads specific to HTTP/2 (e.g.,header compression attacks).|
|  Observe if the application is vulnerable toHTTP/2-specific attacks.|
|45. Testing forWebSocket Vulnerabilities|
| |
|        Test Case 45.1: Test for WebSocket handshake vulnerabilities |
|o   Steps: |
|  Identify WebSocket connections in theapplication.|
|  Capture and modify the WebSocket handshakerequest.|
|  Observe if the application properly validatesthe handshake.|
|        Test Case 45.2: Test for WebSocket message tampering |
|o   Steps: |
|  Capture WebSocket messages using Burp Suite.|
|  Modify the messages and resend them.|
|  Observe if the application properly validatesand processes the modified messages.|
|46. Testing for GraphQL Vulnerabilities|
| |
|        Test Case 46.1: Test for GraphQL introspection |
|o   Steps: |
|  Identify GraphQLendpoints in the application.|
|  Send introspection queries to discover theschema.|
|  Observe if the application exposes sensitiveinformation through introspection.|
|        Test Case 46.2: Test for GraphQL injection |
|o   Steps: |
|  Identify input fields that accept GraphQL queries.|
|  Inject malicious GraphQLqueries (e.g., nested queries to cause denial of service).|
|  Observe if the application processes themalicious queries.|
|47. Testing forServer-Side Template Injection (SSTI)|
| |
|        Test Case 47.1: Test for SSTI in template rendering |
|o   Steps: |
|  Identify input fields that are rendered usingserver-side templates.|
|  Inject template-specific payloads (e.g., {{7*7}} for Jinja2).|
|  Observe if the application executes theinjected template code.|
|        Test Case 47.2: Test for SSTI in email templates |
|o   Steps: |
|  Identify functionalities that send emailsusing server-side templates.|
|  Inject template-specific payloads in theinput fields.|
|  Observe if the application executes theinjected template code in the email.|
|48. Testing forBusiness Logic Vulnerabilities|
| |
|        Test Case 48.1: Test for race conditions |
|o   Steps: |
|  Identify functionalities that could beaffected by race conditions (e.g., financial transactions).|
|  Use tools like Burp Suite's Intruder to sendmultiple concurrent requests.|
|  Observe if the application properly handlesconcurrent requests.|
|        Test Case 48.2: Test for improper validation of multi-step processes |
|o   Steps: |
|  Identify multi-step processes (e.g.,registration, checkout).|
|  Attempt to skip steps or perform steps out oforder.|
|  Observe if the application properly validatesthe process flow.|
|49. Testing forOAuth/OpenID Connect Vulnerabilities|
| |
|        Test Case 49.1: Test for improper implementation of OAuth flows |
|o   Steps: |
|  Identify OAuth flows used by the application(e.g., authorization code flow).|
|  Attempt to manipulate the flow (e.g., reuseauthorization codes).|
|  Observe if the application properly validatesthe OAuth flow.|
|        Test Case 49.2: Test for ID token manipulation in OpenID Connect |
|o   Steps: |
|  Capture ID tokens used by the application.|
|  Modify the payload of the ID token (e.g.,change user claims).|
|  Observe if the application properly validatesthe modified ID token.|
|50. Testing forCloud-Specific Vulnerabilities|
| |
|        Test Case 50.1: Test for misconfigured cloud storage |
|o   Steps: |
|  Identify cloud storage services used by theapplication (e.g., AWS S3).|
|  Check if the storage is publicly accessible.|
|  Attempt to access and modify the stored data.|
|        Test Case 50.2: Test for insecure cloud API keys |
|o   Steps: |
|  Identify cloud API keys used by theapplication.|
|  Check if the keys are exposed in theclient-side code or configuration files.|
|  Attempt to use the exposed keys to accesscloud services.|
|51. Testing forDependency Vulnerabilities|
| |
|        Test Case 51.1: Test for outdated dependencies |
|o   Steps: |
|  Identify dependencies used by the application(e.g., libraries, frameworks).|
|  Check if any dependencies are outdated orhave known vulnerabilities.|
|  Observe if the application is vulnerable dueto outdated dependencies.|
|        Test Case 51.2: Test for vulnerable third-party components |
|o   Steps: |
|  Identify third-party components used by theapplication (e.g., plugins, modules).|
|  Check if any components have knownvulnerabilities.|
|  Observe if the application is vulnerable dueto third-party components.|
|52. Testing forCross-Site Script Inclusion (XSSI)|
| |
|        Test Case 52.1: Test for XSSI in JSON responses |
|o   Steps: |
|  Identify endpoints that return JSONresponses.|
|  Attempt to include the JSON response in a maliciousscript tag.|
|  Observe if the application is vulnerable toXSSI.|
|        Test Case 52.2: Test for XSSI in script responses |
|o   Steps: |
|  Identify endpoints that return scriptresponses.|
|  Attempt to include the script response in amalicious script tag.|
|  Observe if the application is vulnerable toXSSI.|
|53. Testing forContent Spoofing|
| |
|        Test Case 53.1: Test for content spoofing in reflected input |
|o   Steps: |
|  Identify input fields that reflect user inputin the response.|
|  Inject payloads that modify the content(e.g., <div>Fake Content</div>).|
|  Observe if the application improperlyreflects and displays the injected content.|
|        Test Case 53.2: Test for content spoofing in URL parameters |
|o   Steps: |
|  Identify URL parameters that are reflected inthe response.|
|  Inject payloads that modify the content (e.g., ?message=<div>Fake Content</div>).|
|  Observe if the application improperlyreflects and displays the injected content.|
|54. Testing forHTTP Smuggling|
| |
|        Test Case 54.1: Test for HTTP request smuggling |
|o   Steps: |
|  Identify endpoints that process HTTPrequests.|
|  Inject payloads that exploit differences inHTTP request parsing (e.g., Transfer-Encoding:chunked).|
|  Observe if the application is vulnerable toHTTP request smuggling.|
|        Test Case 54.2: Test for HTTP response smuggling |
|o   Steps: |
|  Identify endpoints that process HTTPresponses.|
|  Inject payloads that exploit differences inHTTP response parsing.|
|  Observe if the application is vulnerable toHTTP response smuggling.|
|55. Testing forCSRF Token Bypass|
| |
|        Test Case 55.1: Test for missing CSRF tokens |
|o   Steps: |
|  Identify functionalities that should beprotected by CSRF tokens (e.g., form submissions).|
|  Capture the request and remove the CSRFtoken.|
|  Observe if the application processes therequest without the CSRF token.|
|        Test Case 55.2: Test for predictable CSRF tokens |
|o   Steps: |
|  Identify functionalities that use CSRFtokens.|
|  Capture multiple CSRF tokens and analyzetheir patterns.|
|  Attempt to predict and use a valid CSRFtoken.|
|56. Testing forDNS Rebinding|
| |
|        Test Case 56.1: Test for DNS rebinding vulnerabilities |
|o   Steps: |
|  Identify endpoints that make DNS requests.|
|  Set up a DNS rebinding attack server.|
|  Observe if the application is vulnerable toDNS rebinding attacks.|
|        Test Case 56.2: Test for DNS rebinding in web applications |
|o   Steps: |
|  Identify functionalities that make DNSrequests (e.g., URL fetch).|
|  Set up a DNS rebinding attack server.|
|  Observe if the application is vulnerable toDNS rebinding attacks.|
|57. Testing forUser Enumeration|
| |
|        Test Case 57.1: Test for user enumeration in login functionality |
|o   Steps: |
|  Identify the login functionality.|
|  Attempt to log in with valid and invalidusernames.|
|  Observe if the application provides differentresponses for valid and invalid usernames.|
|        Test Case 57.2: Test for user enumeration in password reset functionality|
|o   Steps: |
|  Identify the password reset functionality.|
|  Attempt to reset passwords for valid andinvalid usernames.|
|  Observe if the application provides differentresponses for valid and invalid usernames.|
|58. Testing forHTTP Parameter Pollution (HPP)|
| |
|        Test Case 58.1: Test for HPP in query parameters |
|o   Steps: |
|  Identify functionalities that accept multiplequery parameters.|
|  Inject duplicate parameters with differentvalues (e.g., param1=value1&param1=value2).|
|  Observe if the application processes theparameters correctly.|
|        Test Case 58.2: Test for HPP in POST data |
|o   Steps: |
|  Identify functionalities that accept POSTdata.|
|  Inject duplicate parameters with differentvalues in the POST body.|
|  Observe if the application processes theparameters correctly.|
|59. Testing forHTTP Host Header Injection|
| |
|        Test Case 59.1: Test for Host header injection in HTTP requests |
|o   Steps: |
|  Capture HTTP requests using Burp Suite.|
|  Modify the Host header to an arbitrary value(e.g., evil.com).|
|  Observe if the application processes themodified Host header.|
|        Test Case 59.2: Test for Host header injection in password reset functionality|
|o   Steps: |
|  Identify password reset functionality.|
|  Capture the request and modify the Hostheader to an arbitrary value.|
|  Observe if the password reset link is sent tothe modified Host.|
|60. Testing forSubdomain Takeover|
| |
|        Test Case 60.1: Test for subdomain takeover vulnerabilities |
|o   Steps: |
|  Identify subdomains used by the application.|
|  Check if any subdomains are pointing tounclaimed resources (e.g., CNAME pointing to a non-existent S3 bucket).|
|  Attempt to claim the unclaimed resource andobserve if the subdomain can be taken over.|
|        Test Case 60.2: Test for dangling DNS records |
|o   Steps: |
|  Identify DNS records for the application.|
|  Check if any DNS records are pointing tounclaimed resources.|
|  Attempt to claim the unclaimed resource andobserve if the DNS record can be taken over.|
| |
