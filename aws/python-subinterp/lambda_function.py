import json
import _xxsubinterpreters as interpreters

# SECURITY VULNERABILITY: Unsafe Execution of User-Controlled Code in Python Subinterpreter
# CWE-94: Improper Control of Generation of Code ('Code Injection')
#
# This function accepts user-provided code and executes it in a Python subinterpreter.
# While subinterpreters provide some isolation, executing arbitrary user code is dangerous
# and can lead to denial of service, resource exhaustion, or information disclosure.

def lambda_handler(event, context):
    """
    AWS Lambda function that executes user-provided Python code in a subinterpreter.

    VULNERABILITIES:
    1. Arbitrary code execution via interpreters.run_string() (CRITICAL)
    2. User-controlled code passed directly to run_in_subinterp equivalent
    3. No sandboxing or resource limits on executed code
    """

    try:
        body = json.loads(event.get('body', '{}'))

        # VULNERABILITY: User-controlled code execution in subinterpreter
        # An attacker can provide malicious Python code to execute
        if 'code' in body:
            user_code = body['code']

            # Create a new subinterpreter
            # DANGEROUS: Executing arbitrary user-provided code
            interp_id = interpreters.create()

            try:
                # VULNERABILITY: run_string() executes user-controlled code
                # This is equivalent to using Py_run_in_subinterp from C API
                interpreters.run_string(interp_id, user_code)

                return {
                    'statusCode': 200,
                    'body': json.dumps({
                        'message': 'Code executed in subinterpreter',
                        'interpreter_id': interp_id
                    })
                }
            finally:
                # Clean up the subinterpreter
                interpreters.destroy(interp_id)

        # Alternative vulnerability pattern using exec in shared namespace
        if 'eval_expr' in body:
            expression = body['eval_expr']
            shared_dict = {}

            # VULNERABILITY: Using exec() on user input, then accessing results
            # This simulates the pattern of running user code and retrieving results
            exec(f"result = {expression}", shared_dict)

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Expression evaluated',
                    'result': str(shared_dict.get('result'))
                })
            }

        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'No code or expression provided'})
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def run_in_subinterp_wrapper(code_string):
    """
    VULNERABILITY: Wrapper function demonstrating run_in_subinterp pattern
    CWE-94: Code Injection via Python subinterpreter execution

    This pattern is seen in Python's test suite and can be dangerous when
    user-controlled input reaches this function.
    """
    interp_id = interpreters.create()
    try:
        # DANGEROUS: Arbitrary code execution
        interpreters.run_string(interp_id, code_string)
    finally:
        interpreters.destroy(interp_id)
