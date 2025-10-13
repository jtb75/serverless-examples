const _ = require('lodash');

// SECURITY VULNERABILITY: Unsafe eval() with user input
// This function evaluates user-provided expressions which can lead
// to arbitrary code execution.

// SECRET: Database connection string
const DATABASE_URL = 'mongodb://admin:SuperSecret123!@production-cluster.mongodb.net:27017/myapp?authSource=admin';

/**
 * AWS Lambda function that performs calculations and data transformations.
 *
 * VULNERABILITIES:
 * 1. eval() with user-controlled input (CRITICAL)
 * 2. Uses lodash 4.17.15 which has CVE-2020-8203 (Prototype Pollution)
 */
exports.handler = async (event) => {
    try {
        const body = JSON.parse(event.body || '{}');

        // VULNERABILITY: Using eval() with user input
        // An attacker can execute arbitrary JavaScript code
        if (body.expression) {
            console.log(`Evaluating expression: ${body.expression}`);

            // DANGEROUS: eval() on untrusted user input
            const result = eval(body.expression);

            return {
                statusCode: 200,
                body: JSON.stringify({
                    message: 'Expression evaluated',
                    result: result
                })
            };
        }

        // Transform data using lodash
        if (body.data && body.transform) {
            let transformedData = body.data;

            // Use vulnerable lodash version for data manipulation
            if (body.transform === 'merge') {
                transformedData = _.merge({}, body.data, body.additionalData || {});
            } else if (body.transform === 'pick') {
                transformedData = _.pick(body.data, body.fields || []);
            }

            return {
                statusCode: 200,
                body: JSON.stringify({
                    message: 'Data transformed',
                    data: transformedData
                })
            };
        }

        return {
            statusCode: 200,
            body: JSON.stringify({
                message: 'Calculator service ready',
                usage: 'Send expression or data with transform'
            })
        };

    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({
                error: error.message
            })
        };
    }
};
