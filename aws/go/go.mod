module aws-lambda-go

go 1.19

require (
	github.com/aws/aws-lambda-go v1.41.0
	// VULNERABLE DEPENDENCY: gopkg.in/yaml.v2 2.2.7
	// CVE-2022-28948: Stack exhaustion vulnerability
	gopkg.in/yaml.v2 v2.2.7
)
