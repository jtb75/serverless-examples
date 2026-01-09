using System;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace VulnerableNetDCS
{
    // SECURITY VULNERABILITY: Insecure Deserialization with NetDataContractSerializer
    // CWE-502: Deserialization of Untrusted Data
    //
    // NetDataContractSerializer is inherently dangerous because it includes
    // full type information in the serialized data, allowing attackers to
    // instantiate arbitrary types and execute code.

    [DataContract]
    public class UserProfile
    {
        [DataMember]
        public string Username { get; set; }

        [DataMember]
        public string Email { get; set; }

        [DataMember]
        public string Role { get; set; }
    }

    [DataContract]
    public class ConfigData
    {
        [DataMember]
        public string Setting { get; set; }

        [DataMember]
        public object Value { get; set; }  // DANGEROUS: object type allows any payload
    }

    public static class VulnerableFunction
    {
        /// <summary>
        /// Azure Function with NetDataContractSerializer deserialization vulnerabilities
        ///
        /// VULNERABILITIES:
        /// 1. NetDataContractSerializer deserializes type information from input (CRITICAL)
        /// 2. No type filtering or allowlisting
        /// 3. Accepts Base64-encoded serialized data from user
        /// 4. Can instantiate dangerous types like ObjectDataProvider, TypeConfuseDelegate
        /// </summary>
        [FunctionName("DeserializeData")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("Processing deserialization request");

            try
            {
                string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
                dynamic data = JsonConvert.DeserializeObject(requestBody);

                string action = data?.action;
                string payload = data?.payload;

                if (string.IsNullOrEmpty(payload))
                {
                    return new BadRequestObjectResult(new { error = "No payload provided" });
                }

                // VULNERABILITY 1: Direct NetDataContractSerializer deserialization
                // CWE-502: This is extremely dangerous as it deserializes type info
                if (action == "deserialize")
                {
                    byte[] bytes = Convert.FromBase64String(payload);

                    // DANGEROUS: NetDataContractSerializer includes CLR type information
                    // in the serialized XML, allowing arbitrary type instantiation
                    var serializer = new NetDataContractSerializer();

                    using (var stream = new MemoryStream(bytes))
                    {
                        // CRITICAL VULNERABILITY: Deserializing untrusted data
                        // An attacker can craft payloads to execute arbitrary code
                        object result = serializer.Deserialize(stream);

                        return new OkObjectResult(new
                        {
                            message = "Data deserialized",
                            type = result?.GetType().FullName
                        });
                    }
                }

                // VULNERABILITY 2: XML string deserialization
                // CWE-502: Same vulnerability with XML string input
                if (action == "deserialize_xml")
                {
                    var serializer = new NetDataContractSerializer();

                    // DANGEROUS: Reading type info from untrusted XML
                    using (var reader = XmlReader.Create(new StringReader(payload)))
                    {
                        object result = serializer.ReadObject(reader);

                        return new OkObjectResult(new
                        {
                            message = "XML deserialized",
                            type = result?.GetType().FullName
                        });
                    }
                }

                // VULNERABILITY 3: Deserialization with expected type (still dangerous)
                // CWE-502: Even expecting UserProfile, nested objects can be exploited
                if (action == "deserialize_profile")
                {
                    byte[] bytes = Convert.FromBase64String(payload);
                    var serializer = new NetDataContractSerializer();

                    using (var stream = new MemoryStream(bytes))
                    {
                        // DANGEROUS: Type expectation doesn't prevent exploitation
                        // Nested objects or properties of type 'object' can contain gadgets
                        var profile = (UserProfile)serializer.Deserialize(stream);

                        return new OkObjectResult(new
                        {
                            username = profile?.Username,
                            email = profile?.Email,
                            role = profile?.Role
                        });
                    }
                }

                // VULNERABILITY 4: Config deserialization with object property
                // CWE-502: Object property allows arbitrary type injection
                if (action == "deserialize_config")
                {
                    byte[] bytes = Convert.FromBase64String(payload);
                    var serializer = new NetDataContractSerializer();

                    using (var stream = new MemoryStream(bytes))
                    {
                        // DANGEROUS: ConfigData.Value is of type object
                        // allowing malicious payloads in that property
                        var config = (ConfigData)serializer.Deserialize(stream);

                        return new OkObjectResult(new
                        {
                            setting = config?.Setting,
                            valueType = config?.Value?.GetType().FullName
                        });
                    }
                }

                return new BadRequestObjectResult(new { error = "Invalid action" });
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Deserialization error");
                return new ObjectResult(new { error = ex.Message })
                {
                    StatusCode = 500
                };
            }
        }
    }
}

/*
 * ATTACK INFORMATION:
 *
 * NetDataContractSerializer is vulnerable to deserialization attacks because
 * it includes full .NET type information in the serialized data (unlike DataContractSerializer).
 *
 * Common gadget chains that can be exploited:
 * - ObjectDataProvider + Process.Start
 * - TypeConfuseDelegate
 * - WindowsIdentity
 * - XamlReader
 *
 * Tools like ysoserial.net can generate payloads:
 * ysoserial.exe -f NetDataContractSerializer -g ObjectDataProvider -c "calc.exe"
 *
 * Microsoft recommends NEVER using NetDataContractSerializer with untrusted data.
 * See: https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide
 */
