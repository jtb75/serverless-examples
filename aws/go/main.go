package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"gopkg.in/yaml.v2"
)

// RequestBody represents the incoming request structure
type RequestBody struct {
	Command    string                 `json:"command"`
	ConfigYAML string                 `json:"config_yaml"`
	Data       map[string]interface{} `json:"data"`
}

// ResponseBody represents the response structure
type ResponseBody struct {
	Message string      `json:"message"`
	Output  string      `json:"output,omitempty"`
	Config  interface{} `json:"config,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// SECURITY VULNERABILITY: Command Injection
// This function executes user-provided commands without proper sanitization,
// allowing arbitrary command execution.
//
// VULNERABILITIES:
// 1. Command injection via exec.Command with user input (CRITICAL)
// 2. Uses gopkg.in/yaml.v2 2.2.7 which has CVE-2022-28948 (Stack exhaustion)

// Handler processes incoming Lambda requests
func Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var reqBody RequestBody

	if err := json.Unmarshal([]byte(request.Body), &reqBody); err != nil {
		return createResponse(400, ResponseBody{Error: "Invalid request body"}), nil
	}

	// VULNERABILITY: Command Injection
	// User input is directly passed to shell command execution
	if reqBody.Command != "" {
		// DANGEROUS: Executing user-controlled commands
		// An attacker can inject commands like: "ls; rm -rf /" or "cat /etc/passwd"
		cmd := exec.Command("sh", "-c", reqBody.Command)
		output, err := cmd.CombinedOutput()

		if err != nil {
			return createResponse(500, ResponseBody{
				Message: "Command execution failed",
				Error:   err.Error(),
			}), nil
		}

		return createResponse(200, ResponseBody{
			Message: "Command executed successfully",
			Output:  string(output),
		}), nil
	}

	// Parse YAML configuration (vulnerable yaml.v2 version)
	if reqBody.ConfigYAML != "" {
		var config map[string]interface{}
		if err := yaml.Unmarshal([]byte(reqBody.ConfigYAML), &config); err != nil {
			return createResponse(400, ResponseBody{Error: "Invalid YAML configuration"}), nil
		}

		return createResponse(200, ResponseBody{
			Message: "Configuration parsed successfully",
			Config:  config,
		}), nil
	}

	return createResponse(200, ResponseBody{
		Message: "System utility service ready",
	}), nil
}

func createResponse(statusCode int, body ResponseBody) events.APIGatewayProxyResponse {
	bodyJSON, _ := json.Marshal(body)
	return events.APIGatewayProxyResponse{
		StatusCode: statusCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(bodyJSON),
	}
}

func main() {
	lambda.Start(Handler)
}
