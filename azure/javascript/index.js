const axios = require('axios');

// SECURITY VULNERABILITY: Prototype Pollution
// This function merges user-provided objects without proper validation,
// allowing attackers to pollute the Object prototype.

// VULNERABILITIES:
// 1. Prototype Pollution via unsafe object merging (HIGH)
// 2. Uses axios 0.21.0 which has CVE-2020-28168 (SSRF vulnerability)

/**
 * Azure Function that merges configuration data and makes HTTP requests.
 */
module.exports = async function (context, req) {
    context.log('JavaScript HTTP trigger function processed a request.');

    try {
        const body = req.body || {};

        // VULNERABILITY: Prototype Pollution
        // Merging user-controlled object without validation
        if (body.config && body.merge) {
            const baseConfig = {
                apiUrl: 'https://api.example.com',
                timeout: 5000,
                retries: 3
            };

            // DANGEROUS: Unsafe merge that can pollute Object.prototype
            // An attacker can send: {"merge": {"__proto__": {"isAdmin": true}}}
            function unsafeMerge(target, source) {
                for (let key in source) {
                    if (typeof source[key] === 'object' && source[key] !== null) {
                        if (!target[key]) target[key] = {};
                        unsafeMerge(target[key], source[key]);
                    } else {
                        target[key] = source[key];
                    }
                }
                return target;
            }

            const mergedConfig = unsafeMerge(baseConfig, body.merge);
            context.log('Merged configuration:', mergedConfig);

            context.res = {
                status: 200,
                body: {
                    message: 'Configuration merged successfully',
                    config: mergedConfig
                }
            };
            return;
        }

        // Make HTTP request using vulnerable axios version
        if (body.url) {
            try {
                const response = await axios.get(body.url, {
                    timeout: 5000,
                    validateStatus: () => true // Accept any status code
                });

                context.res = {
                    status: 200,
                    body: {
                        message: 'HTTP request completed',
                        statusCode: response.status,
                        dataLength: response.data ? JSON.stringify(response.data).length : 0
                    }
                };
                return;
            } catch (error) {
                context.res = {
                    status: 500,
                    body: {
                        error: error.message
                    }
                };
                return;
            }
        }

        context.res = {
            status: 200,
            body: {
                message: 'Configuration service ready',
                usage: 'Send config with merge object or url for HTTP request'
            }
        };

    } catch (error) {
        context.log.error('Error:', error);
        context.res = {
            status: 500,
            body: {
                error: error.message
            }
        };
    }
};
