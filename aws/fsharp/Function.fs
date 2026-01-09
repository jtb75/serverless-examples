namespace VulnerableFsPickler

open System
open System.IO
open Amazon.Lambda.Core
open Amazon.Lambda.APIGatewayEvents
open MBrace.FsPickler
open MBrace.FsPickler.Json
open Newtonsoft.Json

// SECURITY VULNERABILITY: Insecure Deserialization with FsPickler
// CWE-502: Deserialization of Untrusted Data
//
// This Lambda function demonstrates insecure deserialization vulnerabilities
// when using FsPickler to deserialize user-provided data without validation.

[<assembly: LambdaSerializer(typeof<Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer>)>]
do ()

// Sample types for deserialization
type UserData = {
    Username: string
    Email: string
    Role: string
}

type Command = {
    Action: string
    Target: string
    Parameters: Map<string, obj>
}

module Handler =
    let binarySerializer = FsPickler.CreateBinarySerializer()
    let jsonSerializer = FsPickler.CreateJsonSerializer()

    /// VULNERABILITY 1: Binary deserialization of untrusted data
    /// CWE-502: Deserializing arbitrary binary data can lead to code execution
    let deserializeBinaryUnsafe (base64Data: string) : obj =
        let bytes = Convert.FromBase64String(base64Data)
        use stream = new MemoryStream(bytes)
        // DANGEROUS: Deserializing untrusted binary data
        // FsPickler can deserialize arbitrary types including those with
        // dangerous side effects in constructors or property setters
        binarySerializer.Deserialize<obj>(stream)

    /// VULNERABILITY 2: JSON deserialization with type information
    /// CWE-502: Type-polymorphic deserialization can instantiate dangerous types
    let deserializeJsonUnsafe (jsonData: string) : obj =
        use reader = new StringReader(jsonData)
        // DANGEROUS: FsPickler JSON includes type metadata
        // Attacker can specify arbitrary types to instantiate
        jsonSerializer.Deserialize<obj>(reader)

    /// VULNERABILITY 3: Deserialization without type constraints
    /// CWE-502: Accepting any type allows gadget chain attacks
    let deserializeAnyType<'T> (base64Data: string) : 'T =
        let bytes = Convert.FromBase64String(base64Data)
        use stream = new MemoryStream(bytes)
        // DANGEROUS: Generic type parameter allows any type
        binarySerializer.Deserialize<'T>(stream)

    let handler (request: APIGatewayProxyRequest) (context: ILambdaContext) =
        /// AWS Lambda function with FsPickler deserialization vulnerabilities
        ///
        /// VULNERABILITIES:
        /// 1. Binary deserialization of user-provided data (CRITICAL)
        /// 2. JSON deserialization with type polymorphism (CRITICAL)
        /// 3. No input validation or type allowlisting
        /// 4. Deserializing to obj type allows any payload
        try
            let body =
                if String.IsNullOrEmpty(request.Body) then
                    "{}"
                else
                    request.Body

            let input = JsonConvert.DeserializeObject<Map<string, string>>(body)

            // VULNERABILITY 1: Direct binary deserialization
            if input.ContainsKey("binary_data") then
                let data = input.["binary_data"]
                // DANGEROUS: Deserializing arbitrary binary from user input
                let result = deserializeBinaryUnsafe data
                APIGatewayProxyResponse(
                    StatusCode = 200,
                    Body = sprintf """{"message": "Deserialized binary data", "type": "%s"}""" (result.GetType().Name)
                )

            // VULNERABILITY 2: JSON deserialization with embedded types
            elif input.ContainsKey("json_data") then
                let data = input.["json_data"]
                // DANGEROUS: FsPickler JSON contains type info that can be exploited
                let result = deserializeJsonUnsafe data
                APIGatewayProxyResponse(
                    StatusCode = 200,
                    Body = sprintf """{"message": "Deserialized JSON data", "type": "%s"}""" (result.GetType().Name)
                )

            // VULNERABILITY 3: Deserializing commands
            elif input.ContainsKey("command_data") then
                let data = input.["command_data"]
                // DANGEROUS: Even with a known type, FsPickler can be tricked
                // to instantiate nested dangerous types
                let command = deserializeAnyType<Command> data
                APIGatewayProxyResponse(
                    StatusCode = 200,
                    Body = sprintf """{"action": "%s", "target": "%s"}""" command.Action command.Target
                )

            else
                APIGatewayProxyResponse(
                    StatusCode = 400,
                    Body = """{"error": "No serialized data provided"}"""
                )

        with ex ->
            context.Logger.LogError(sprintf "Error: %s" ex.Message)
            APIGatewayProxyResponse(
                StatusCode = 500,
                Body = sprintf """{"error": "%s"}""" ex.Message
            )
