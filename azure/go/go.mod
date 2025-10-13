module azure-function-go

go 1.19

require (
	// VULNERABLE DEPENDENCY: golang.org/x/crypto
	// Using older version with potential vulnerabilities
	// CVE-2020-9283: Processing of crafted public keys can cause panic
	golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975
)
