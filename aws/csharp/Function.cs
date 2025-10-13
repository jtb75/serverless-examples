using System;
using System.Data.SqlClient;
using System.Collections.Generic;
using Amazon.Lambda.Core;
using Amazon.Lambda.APIGatewayEvents;
using Newtonsoft.Json;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace AwsLambdaCSharp
{
    /// <summary>
    /// AWS Lambda function for user data queries.
    ///
    /// VULNERABILITIES:
    /// 1. SQL Injection - User input concatenated directly into SQL query (CRITICAL)
    /// 2. Uses Newtonsoft.Json 12.0.1 which has CVE-2024-21907 (DoS vulnerability)
    /// </summary>
    public class Function
    {
        /// <summary>
        /// Lambda function handler that processes user search queries.
        /// </summary>
        public APIGatewayProxyResponse FunctionHandler(APIGatewayProxyRequest request, ILambdaContext context)
        {
            try
            {
                var requestBody = JsonConvert.DeserializeObject<Dictionary<string, string>>(request.Body);

                if (requestBody.ContainsKey("username"))
                {
                    string username = requestBody["username"];

                    // VULNERABILITY: SQL Injection
                    // User input is directly concatenated into SQL query without parameterization
                    string connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING")
                        ?? "Server=localhost;Database=users;User Id=sa;Password=P@ssw0rd;";

                    using (SqlConnection connection = new SqlConnection(connectionString))
                    {
                        // DANGEROUS: SQL Injection vulnerability
                        // An attacker can inject malicious SQL like: ' OR '1'='1' --
                        string query = "SELECT * FROM Users WHERE Username = '" + username + "'";

                        context.Logger.LogLine($"Executing query: {query}");

                        SqlCommand command = new SqlCommand(query, connection);

                        try
                        {
                            connection.Open();
                            SqlDataReader reader = command.ExecuteReader();

                            var results = new List<Dictionary<string, object>>();
                            while (reader.Read())
                            {
                                var row = new Dictionary<string, object>();
                                for (int i = 0; i < reader.FieldCount; i++)
                                {
                                    row[reader.GetName(i)] = reader.GetValue(i);
                                }
                                results.Add(row);
                            }

                            return new APIGatewayProxyResponse
                            {
                                StatusCode = 200,
                                Body = JsonConvert.SerializeObject(new
                                {
                                    message = "Query executed successfully",
                                    results = results,
                                    count = results.Count
                                }),
                                Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } }
                            };
                        }
                        catch (Exception dbEx)
                        {
                            context.Logger.LogLine($"Database error: {dbEx.Message}");
                        }
                    }
                }

                return new APIGatewayProxyResponse
                {
                    StatusCode = 200,
                    Body = JsonConvert.SerializeObject(new { message = "Please provide a username to search" }),
                    Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } }
                };
            }
            catch (Exception ex)
            {
                context.Logger.LogLine($"Error: {ex.Message}");
                return new APIGatewayProxyResponse
                {
                    StatusCode = 500,
                    Body = JsonConvert.SerializeObject(new { error = ex.Message }),
                    Headers = new Dictionary<string, string> { { "Content-Type", "application/json" } }
                };
            }
        }
    }
}
