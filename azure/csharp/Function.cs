using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Xml;

namespace AzureFunctionCSharp
{
    /// <summary>
    /// Azure Function for XML data processing.
    ///
    /// VULNERABILITIES:
    /// 1. XML External Entity (XXE) injection - Unsafe XML parsing (HIGH)
    /// 2. Uses vulnerable XML parsing configuration that allows external entities
    /// </summary>
    public static class Function
    {
        [FunctionName("XmlProcessor")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                dynamic data = JsonConvert.DeserializeObject(requestBody);

                // VULNERABILITY: XXE (XML External Entity) Injection
                // Processing XML without disabling external entity resolution
                if (data?.xmlData != null)
                {
                    string xmlContent = data.xmlData.ToString();
                    log.LogInformation($"Processing XML data: {xmlContent.Substring(0, Math.Min(100, xmlContent.Length))}...");

                    // DANGEROUS: XmlDocument without proper security settings
                    // An attacker can include external entities like:
                    // <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                    XmlDocument xmlDoc = new XmlDocument();

                    // These settings make it vulnerable to XXE attacks
                    xmlDoc.XmlResolver = new XmlUrlResolver(); // Allows external resources

                    try
                    {
                        xmlDoc.LoadXml(xmlContent);

                        // Extract data from XML
                        XmlNodeList nodes = xmlDoc.SelectNodes("//data");
                        int nodeCount = nodes?.Count ?? 0;

                        return new OkObjectResult(new
                        {
                            message = "XML processed successfully",
                            nodeCount = nodeCount,
                            rootElement = xmlDoc.DocumentElement?.Name
                        });
                    }
                    catch (XmlException xmlEx)
                    {
                        log.LogError($"XML parsing error: {xmlEx.Message}");
                        return new BadRequestObjectResult(new
                        {
                            error = "Invalid XML format",
                            details = xmlEx.Message
                        });
                    }
                }

                // Process JSON configuration
                if (data?.config != null)
                {
                    return new OkObjectResult(new
                    {
                        message = "Configuration received",
                        configKeys = data.config
                    });
                }

                return new OkObjectResult(new
                {
                    message = "XML processing service ready",
                    usage = "Send POST with 'xmlData' field containing XML content"
                });
            }
            catch (Exception ex)
            {
                log.LogError($"Error: {ex.Message}");
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }
    }
}
