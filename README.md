# Serverless Security Testing Examples

This repository contains intentionally vulnerable serverless functions for AWS Lambda and Azure Functions across multiple programming languages. These examples are designed to simulate real-world security vulnerabilities for testing security scanning tools in CI/CD pipelines.

## ⚠️ WARNING

**DO NOT DEPLOY THESE FUNCTIONS TO PRODUCTION ENVIRONMENTS**

This repository contains intentionally vulnerable code and dependencies for security testing purposes only. These functions should only be used in isolated testing environments.

## Repository Structure

```
.
├── aws/
│   ├── python/         # Python Lambda with Pickle deserialization vulnerability
│   │   ├── lambda_function.py
│   │   ├── requirements.txt
│   │   ├── template.yaml
│   │   └── .env (MongoDB password, Git credentials)
│   ├── python-subinterp/  # Python Lambda with subinterpreter code injection (CWE-94)
│   │   ├── lambda_function.py
│   │   ├── requirements.txt
│   │   ├── template.yaml
│   │   └── .env
│   ├── javascript/     # Node.js Lambda with eval() vulnerability
│   │   ├── index.js (MongoDB password in source)
│   │   ├── package.json
│   │   ├── template.yaml
│   │   └── .env (MongoDB password)
│   ├── javascript-sequelize/  # Node.js Lambda with SQL injection in Sequelize (CWE-89)
│   │   ├── index.js
│   │   ├── package.json
│   │   ├── template.yaml
│   │   └── .env
│   ├── java/          # Java Lambda with deserialization vulnerability
│   │   ├── Handler.java
│   │   ├── pom.xml
│   │   └── template.yaml
│   ├── csharp/        # C# Lambda with SQL injection vulnerability
│   │   ├── Function.cs
│   │   ├── AwsLambdaCSharp.csproj
│   │   ├── template.yaml
│   │   └── .env (AWS Access Key)
│   ├── fsharp/        # F# Lambda with FsPickler insecure deserialization (CWE-502)
│   │   ├── Function.fs
│   │   ├── VulnerableFsPickler.fsproj
│   │   ├── template.yaml
│   │   └── .env
│   └── go/            # Go Lambda with command injection vulnerability
│       ├── main.go
│       ├── go.mod
│       ├── template.yaml
│       └── .env (MongoDB password)
└── azure/
    ├── python/        # Python Function with command injection vulnerability
    │   ├── __init__.py
    │   ├── requirements.txt
    │   ├── function.json
    │   └── .env (all secret types)
    ├── javascript/    # Node.js Function with prototype pollution vulnerability
    │   ├── index.js
    │   ├── package.json
    │   ├── function.json
    │   └── .env (all secret types)
    ├── javascript-xxe/  # Node.js Function with XXE vulnerability via libxml (CWE-611)
    │   ├── index.js
    │   ├── package.json
    │   ├── function.json
    │   ├── host.json
    │   └── .env
    ├── java/          # Java Function with vulnerable dependency (clean code)
    │   ├── Function.java
    │   ├── pom.xml
    │   └── function.json
    ├── csharp/        # C# Function with XXE vulnerability
    │   ├── Function.cs
    │   ├── AzureFunctionCSharp.csproj
    │   ├── host.json
    │   └── .env (all secret types)
    ├── csharp-netdcs/  # C# Function with NetDataContractSerializer insecure deserialization (CWE-502)
    │   ├── Function.cs
    │   ├── VulnerableNetDCS.csproj
    │   ├── function.json
    │   ├── host.json
    │   └── .env
    └── go/            # Go Function with path traversal vulnerability
        ├── handler.go
        ├── go.mod
        ├── function.json
        ├── host.json
        └── .env (all secret types)
```

## Vulnerability Summary

### AWS Lambda Functions

| Language   | Code Vulnerability | Vulnerable Dependency | CVE/CWE |
|------------|-------------------|----------------------|-----------|
| **Python** | Insecure Pickle Deserialization | Pillow 8.0.0 | CVE-2021-25287, CVE-2021-25288 |
| **Python (subinterp)** | Subinterpreter Code Injection | PyYAML 5.3.1 | CWE-94 |
| **JavaScript** | eval() with user input | lodash 4.17.15 | CVE-2020-8203 |
| **JavaScript (Sequelize)** | SQL Injection in Sequelize | lodash 4.17.15 | CWE-89 |
| **Java** | ObjectInputStream Deserialization | log4j 2.14.1 | CVE-2021-44228 (Log4Shell) |
| **C#** | SQL Injection | Newtonsoft.Json 12.0.1 | CVE-2024-21907 |
| **F#** | FsPickler Insecure Deserialization | Newtonsoft.Json 12.0.1 | CWE-502 |
| **Go** | Command Injection (os/exec) | gopkg.in/yaml.v2 2.2.7 | CVE-2022-28948 |

### Azure Functions

| Language   | Code Vulnerability | Vulnerable Dependency | CVE/CWE |
|------------|-------------------|----------------------|-----------|
| **Python** | Command Injection (os.system) | requests 2.20.0 | CVE-2018-18074 |
| **JavaScript** | Prototype Pollution | axios 0.21.0 | CVE-2020-28168 |
| **JavaScript (XXE)** | XXE via libxmljs2 | libxmljs2 0.31.0 | CWE-611 |
| **Java** | None (clean code) | commons-collections 3.2.1 | CVE-2015-6420, CVE-2015-7501 |
| **C#** | XML External Entity (XXE) | Newtonsoft.Json 12.0.1 | CVE-2024-21907 |
| **C# (NetDCS)** | NetDataContractSerializer Deserialization | Newtonsoft.Json 12.0.1 | CWE-502 |
| **Go** | Path Traversal | golang.org/x/crypto (old) | CVE-2020-9283 |

## Detailed Vulnerability Descriptions

### AWS Functions

#### Python - Image Processor (`aws/python/`)
- **Code Vulnerability**: Uses `pickle.loads()` on base64-decoded user input, allowing arbitrary code execution
- **Dependency Vulnerability**: Pillow 8.0.0 has buffer overflow vulnerabilities in image processing
- **Attack Vector**: Send malicious pickled object in `user_prefs` field

#### JavaScript - Calculator Service (`aws/javascript/`)
- **Code Vulnerability**: Uses `eval()` to evaluate user-provided mathematical expressions
- **Dependency Vulnerability**: lodash 4.17.15 vulnerable to prototype pollution
- **Attack Vector**: Send malicious JavaScript code in `expression` field

#### Java - Data Processor (`aws/java/`)
- **Code Vulnerability**: Uses `ObjectInputStream` to deserialize user-provided data without validation
- **Dependency Vulnerability**: log4j 2.14.1 vulnerable to Log4Shell (RCE via JNDI lookup)
- **Attack Vector**: Send malicious serialized Java object or JNDI lookup string in logs

#### C# - User Query Service (`aws/csharp/`)
- **Code Vulnerability**: SQL query constructed via string concatenation with user input
- **Dependency Vulnerability**: Newtonsoft.Json 12.0.1 has DoS vulnerability
- **Attack Vector**: SQL injection via `username` field (e.g., `' OR '1'='1' --`)

#### Go - System Utility (`aws/go/`)
- **Code Vulnerability**: Executes shell commands with user-controlled input via `exec.Command`
- **Dependency Vulnerability**: gopkg.in/yaml.v2 2.2.7 has stack exhaustion vulnerability
- **Attack Vector**: Command injection via `command` field (e.g., `ls; cat /etc/passwd`)

#### Python - Subinterpreter Code Execution (`aws/python-subinterp/`)
- **Code Vulnerability**: Uses `_xxsubinterpreters.run_string()` to execute user-provided Python code in a subinterpreter
- **Dependency Vulnerability**: PyYAML 5.3.1 allows arbitrary code execution
- **CWE**: CWE-94 (Improper Control of Generation of Code)
- **Attack Vector**: Send malicious Python code in `code` or `eval_expr` field

#### JavaScript - Sequelize SQL Injection (`aws/javascript-sequelize/`)
- **Code Vulnerability**: Multiple SQL injection patterns including raw queries with string concatenation, `Sequelize.literal()` with user input, and dynamic column names
- **Dependency Vulnerability**: lodash 4.17.15 vulnerable to prototype pollution
- **CWE**: CWE-89 (SQL Injection)
- **Attack Vector**: SQL injection via `search`, `filter`, `orderBy`, or `column` fields

#### F# - FsPickler Deserialization (`aws/fsharp/`)
- **Code Vulnerability**: Uses FsPickler to deserialize user-provided binary and JSON data without type validation
- **Dependency Vulnerability**: Newtonsoft.Json 12.0.1 has DoS vulnerability
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Attack Vector**: Send malicious serialized FsPickler payload in `binary_data` or `json_data` field

### Azure Functions

#### Python - Diagnostic Service (`azure/python/`)
- **Code Vulnerability**: Uses `os.system()` to execute user-provided system commands
- **Dependency Vulnerability**: requests 2.20.0 vulnerable to CRLF injection
- **Attack Vector**: Command injection via `system_command` field

#### JavaScript - Configuration Service (`azure/javascript/`)
- **Code Vulnerability**: Unsafe object merging allowing prototype pollution
- **Dependency Vulnerability**: axios 0.21.0 vulnerable to SSRF
- **Attack Vector**: Prototype pollution via `merge` field with `__proto__` payload

#### Java - Data Transformer (`azure/java/`)
- **Code Vulnerability**: None - demonstrates vulnerable dependency only
- **Dependency Vulnerability**: commons-collections 3.2.1 vulnerable to deserialization RCE
- **Attack Vector**: Dependency scanning will detect vulnerable library

#### C# - XML Processor (`azure/csharp/`)
- **Code Vulnerability**: XmlDocument with XmlResolver enabled, allowing XXE attacks
- **Dependency Vulnerability**: Newtonsoft.Json 12.0.1 has DoS vulnerability
- **Attack Vector**: XXE injection via `xmlData` field with external entity definitions

#### Go - File Service (`azure/go/`)
- **Code Vulnerability**: Path traversal via unsanitized file path construction
- **Dependency Vulnerability**: golang.org/x/crypto old version with panic vulnerability
- **Attack Vector**: Path traversal via `filename` field (e.g., `../../etc/passwd`)

#### JavaScript - XXE with libxml (`azure/javascript-xxe/`)
- **Code Vulnerability**: Parses XML with `libxmljs2` using `noent: true` and `dtdload: true`, enabling external entity resolution
- **Dependency Vulnerability**: lodash 4.17.15 vulnerable to prototype pollution, xmldom 0.6.0
- **CWE**: CWE-611 (Improper Restriction of XML External Entity Reference)
- **Attack Vector**: Send XML with external entity definitions to read local files or perform SSRF

#### C# - NetDataContractSerializer Deserialization (`azure/csharp-netdcs/`)
- **Code Vulnerability**: Uses `NetDataContractSerializer.Deserialize()` on user-provided data, which includes full CLR type information
- **Dependency Vulnerability**: Newtonsoft.Json 12.0.1 has DoS vulnerability
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Attack Vector**: Send ysoserial.net gadget chain payload (e.g., ObjectDataProvider) in `payload` field

## Use Cases

This repository is ideal for testing:

1. **Static Application Security Testing (SAST)** tools
   - Code-level vulnerability detection
   - Unsafe function usage identification
   - Input validation analysis

2. **Software Composition Analysis (SCA)** tools
   - Vulnerable dependency detection
   - CVE identification
   - License compliance checking

3. **CI/CD Pipeline Security**
   - Pre-deployment security gates
   - Automated security scanning
   - Build-time vulnerability detection

4. **Secrets Scanning**
   - Hardcoded credentials detection
   - API keys and tokens identification
   - Private key exposure detection
   - Environment variable analysis
   - Configuration file scanning

## Included Test Secrets

This repository includes intentional test secrets to validate secret scanning capabilities. Secrets are strategically distributed across functions for comprehensive testing.

### Secret Types Included

The repository contains 4 specific secret types:

1. **AWS Access Key** (with Secret Key)
   ```
   AWS_ACCESS_KEY=ASIA6MDRM2O8A2C85P2H
   AWS_SECRET_KEY=T8zN+D2wN657XQ/J/2S867+e2/X57y8Q567kX3pT
   ```

2. **Password in URL** (MongoDB connection string)
   ```
   MONGODB_URI=mongodb+srv://dbadmin:VerySecretPass2024@cluster0.mongodb.net/production?retryWrites=true
   ```

3. **Azure SAS Token** (Storage Account URL with signature)
   ```
   AZURE_STORAGE_SAS_URL=https://md-ch10tghzrdkv.blob.core.windows.net/$system/...
   ```

4. **Git Credentials** (embedded in URL)
   ```
   GIT_REPO_URL=https://developer:MyGitP@ssw0rd2024@github.com/myorg/myrepo.git
   ```

### Secret Distribution

**AWS Functions:**
- `aws/python/.env`: MongoDB password, Git credentials
- `aws/javascript/.env` + `index.js`: MongoDB password (both in .env and source code)
- `aws/java`: No secrets
- `aws/csharp/.env`: AWS Access Key
- `aws/go/.env`: MongoDB password

**Azure Functions:**
- All Azure functions (`python`, `javascript`, `csharp`, `go`) contain all 4 secret types in their `.env` files for comprehensive testing

## Scanning with Wiz CLI

This repository is designed to be scanned using Wiz CLI for comprehensive security analysis.

### Directory Scanning

Scan individual function directories for vulnerabilities, secrets, and malware:

```bash
# Scan AWS Python function
wizcli dir scan --path aws/python

# Scan Azure JavaScript function
wizcli dir scan --path azure/javascript

# Scan entire AWS directory
wizcli dir scan --path aws

# Enable sensitive data scanning
wizcli dir scan --path . --sensitive-data
```

### IaC Scanning

Scan cloud configuration files for security misconfigurations:

```bash
# Scan AWS SAM templates
wizcli iac scan --path aws --types Cloudformation

# Scan with specific policy
wizcli iac scan --path . --policy "your-policy-name"

# Enable secret scanning in IaC files
wizcli iac scan --path . --secrets
```

For detailed usage information, refer to the included `dir_scan.md` and `iac_scan.md` documentation files.

## File Manifest

Each function directory contains:
- **Source code file(s)** with vulnerable implementations
- **Dependency manifest** (requirements.txt, package.json, pom.xml, etc.) with vulnerable versions
- **Cloud provider configuration** (template.yaml for AWS SAM, function.json for Azure)
- **`.env` file** (where applicable) with test credentials
- **Inline comments** documenting vulnerabilities

## Contributing

This repository is for testing purposes. If you want to add additional vulnerability examples:
1. Ensure vulnerabilities are well-documented with CVE numbers
2. Add clear comments explaining the security issue
3. Update this README with new vulnerability details
4. Follow the existing directory structure

## Disclaimer

These functions are intentionally insecure and should never be deployed to production environments. They are provided solely for educational and security testing purposes. The authors are not responsible for any misuse of this code.

## License

This project is provided as-is for security testing and educational purposes.
