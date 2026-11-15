# Held-out results

Manifest sha256: `cd529aecdcdded28c9ecbf25f5aabbab1839593047b83beb079df1f83d5c881c`

## Taint classes (sinkline has rules for these)

| tool | TP | FN | FP | precision (95% CI) | recall (95% CI) | F1 | macro recall | seconds |
|---|---|---|---|---|---|---|---|---|
| sinkline | 88 | 131 | 26 | 0.77 (0.69-0.84) | 0.40 (0.34-0.47) | 0.53 | 0.62 | 8.7 |
| sinkline-no-interproc | 88 | 131 | 26 | 0.77 (0.69-0.84) | 0.40 (0.34-0.47) | 0.53 | 0.62 | 11.6 |
| sinkline-no-guards | 91 | 128 | 39 | 0.70 (0.62-0.77) | 0.42 (0.35-0.48) | 0.52 | 0.62 | 9.8 |
| bandit | 34 | 185 | 10 | 0.77 (0.63-0.87) | 0.16 (0.11-0.21) | 0.26 | 0.21 | 1.9 |
| semgrep | 53 | 166 | 62 | 0.46 (0.37-0.55) | 0.24 (0.19-0.30) | 0.32 | 0.16 | 26.0 |

## Property classes (sinkline does not attempt these)

| tool | TP | FN | FP | precision (95% CI) | recall (95% CI) | F1 | macro recall | seconds |
|---|---|---|---|---|---|---|---|---|
| sinkline | 0 | 127 | 1 | 0.00 (0.00-0.79) | 0.00 (0.00-0.03) | 0.00 | 0.00 | 8.7 |
| sinkline-no-interproc | 0 | 127 | 1 | 0.00 (0.00-0.79) | 0.00 (0.00-0.03) | 0.00 | 0.00 | 11.6 |
| sinkline-no-guards | 0 | 127 | 1 | 0.00 (0.00-0.79) | 0.00 (0.00-0.03) | 0.00 | 0.00 | 9.8 |
| bandit | 30 | 97 | 12 | 0.71 (0.56-0.83) | 0.24 (0.17-0.32) | 0.36 | 0.31 | 1.9 |
| semgrep | 23 | 104 | 10 | 0.70 (0.53-0.83) | 0.18 (0.12-0.26) | 0.29 | 0.17 | 26.0 |

## Per directory (TP / FN / FP)

| directory | tier | sinkline | sinkline-no-interproc | sinkline-no-guards | bandit | semgrep |
|---|---|---|---|---|---|---|
| CWE-022-PathInjection | taint | 10/7/3 | 10/7/3 | 12/5/7 | 0/17/0 | 2/15/1 |
| CWE-022-TarSlip | taint | 5/6/4 | 5/6/4 | 5/6/4 | 7/4/4 | 0/11/0 |
| CWE-074-TemplateInjection | taint | 2/0/0 | 2/0/0 | 2/0/0 | 1/1/0 | 0/2/0 |
| CWE-078-CommandInjection | taint | 7/5/0 | 7/5/0 | 7/5/1 | 12/0/2 | 12/0/19 |
| CWE-079-Jinja2WithoutEscaping | property | 0/6/1 | 0/6/1 | 0/6/1 | 3/3/1 | 0/6/0 |
| CWE-079-ReflectedXss | taint | 1/1/0 | 1/1/0 | 1/1/0 | 0/2/0 | 0/2/0 |
| CWE-089-SqlInjection | taint | 10/11/0 | 10/11/0 | 10/11/0 | 10/11/2 | 2/19/0 |
| CWE-090-LdapInjection | taint | 4/1/0 | 4/1/0 | 4/1/0 | 0/5/0 | 0/5/0 |
| CWE-094-CodeInjection | taint | 3/0/0 | 3/0/0 | 3/0/1 | 0/3/0 | 3/0/3 |
| CWE-1004-NonHttpOnlyCookie | property | 0/3/0 | 0/3/0 | 0/3/0 | 0/3/0 | 0/3/0 |
| CWE-117-LogInjection | taint | 1/3/1 | 1/3/1 | 1/3/1 | 0/4/0 | 0/4/0 |
| CWE-1275-SameSiteNoneCookie | property | 0/2/0 | 0/2/0 | 0/2/0 | 0/2/0 | 0/2/0 |
| CWE-209-StackTraceExposure | property | 0/5/0 | 0/5/0 | 0/5/0 | 0/5/0 | 0/5/0 |
| CWE-215-FlaskDebug | property | 0/6/0 | 0/6/0 | 0/6/0 | 2/4/0 | 3/3/0 |
| CWE-285-PamAuthorization | property | 0/1/0 | 0/1/0 | 0/1/0 | 0/1/0 | 0/1/0 |
| CWE-295-MissingHostKeyValidation | property | 0/5/0 | 0/5/0 | 0/5/0 | 5/0/0 | 0/5/0 |
| CWE-295-RequestWithoutValidation | property | 0/6/0 | 0/6/0 | 0/6/0 | 2/4/0 | 0/6/0 |
| CWE-312-CleartextLogging | property | 0/26/0 | 0/26/0 | 0/26/0 | 0/26/0 | 2/24/0 |
| CWE-312-CleartextStorage-py3 | property | 0/3/0 | 0/3/0 | 0/3/0 | 0/3/0 | 0/3/0 |
| CWE-326-WeakCryptoKey | property | 0/9/0 | 0/9/0 | 0/9/0 | 0/9/3 | 2/7/3 |
| CWE-327-BrokenCryptoAlgorithm | property | 0/4/0 | 0/4/0 | 0/4/0 | 2/2/1 | 1/3/0 |
| CWE-327-InsecureDefaultProtocol | property | 0/1/0 | 0/1/0 | 0/1/0 | 1/0/0 | 1/0/1 |
| CWE-327-InsecureProtocol | property | 0/28/0 | 0/28/0 | 0/28/0 | 4/24/0 | 8/20/5 |
| CWE-327-WeakSensitiveDataHashing | property | 0/6/0 | 0/6/0 | 0/6/0 | 4/2/0 | 4/2/0 |
| CWE-377-InsecureTemporaryFile | property | 0/3/0 | 0/3/0 | 0/3/0 | 1/2/0 | 0/3/0 |
| CWE-502-UnsafeDeserialization | taint | 4/1/0 | 4/1/0 | 4/1/0 | 4/1/2 | 0/5/0 |
| CWE-601-UrlRedirect | taint | 9/0/10 | 9/0/10 | 9/0/12 | 0/9/0 | 0/9/0 |
| CWE-611-Xxe | taint | 2/0/2 | 2/0/2 | 2/0/2 | 0/2/0 | 0/2/0 |
| CWE-614-InsecureCookie | property | 0/3/0 | 0/3/0 | 0/3/0 | 0/3/0 | 0/3/0 |
| CWE-643-XPathInjection | taint | 4/2/0 | 4/2/0 | 4/2/0 | 0/6/0 | 0/6/0 |
| CWE-730-RegexInjection | taint | 4/4/0 | 4/4/0 | 4/4/0 | 0/8/0 | 0/8/0 |
| CWE-732-WeakFilePermissions | property | 0/6/0 | 0/6/0 | 0/6/0 | 5/1/0 | 2/4/0 |
| CWE-798-HardcodedCredentials | property | 0/2/0 | 0/2/0 | 0/2/0 | 1/1/7 | 0/2/0 |
| CWE-918-ServerSideRequestForgery | taint | 22/67/6 | 22/67/6 | 23/66/11 | 0/89/0 | 34/55/39 |
| CWE-942-CorsMisconfigurationMiddleware | property | 0/2/0 | 0/2/0 | 0/2/0 | 0/2/0 | 0/2/1 |
| CWE-943-NoSqlInjection | taint | 0/23/0 | 0/23/0 | 0/23/0 | 0/23/0 | 0/23/0 |

FP counts every in-class finding that is not matched to a labeled positive line. Findings of a CWE outside the directory's class are ignored: sinkline: 11, sinkline-no-interproc: 3, sinkline-no-guards: 11, bandit: 68, semgrep: 21.
