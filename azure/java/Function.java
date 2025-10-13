package com.function;

import com.microsoft.azure.functions.annotation.*;
import com.microsoft.azure.functions.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Azure Function for data transformation and collection processing.
 *
 * VULNERABILITIES:
 * 1. Uses commons-collections 3.2.1 which has CVE-2015-6420 (Deserialization RCE)
 *    Note: This function has clean code but vulnerable dependency for variety in testing
 */
public class Function {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Azure Function HTTP trigger that processes collections and data transformations.
     * This function demonstrates a vulnerable dependency without code-level vulnerabilities.
     */
    @FunctionName("DataTransformer")
    public HttpResponseMessage run(
            @HttpTrigger(
                name = "req",
                methods = {HttpMethod.POST},
                authLevel = AuthorizationLevel.FUNCTION)
                HttpRequestMessage<Optional<String>> request,
            final ExecutionContext context) {

        context.getLogger().info("Java HTTP trigger processed a request.");

        try {
            String body = request.getBody().orElse("{}");
            Map<String, Object> requestData = objectMapper.readValue(body, Map.class);

            // Safe data processing - no code vulnerabilities
            if (requestData.containsKey("data")) {
                List<Object> data = (List<Object>) requestData.get("data");

                // Perform simple transformations
                Map<String, Object> result = new HashMap<>();
                result.put("originalSize", data.size());
                result.put("processed", true);
                result.put("timestamp", System.currentTimeMillis());

                // Filter and transform data safely
                List<Object> transformedData = new ArrayList<>();
                for (Object item : data) {
                    if (item != null) {
                        transformedData.add(item);
                    }
                }
                result.put("transformedSize", transformedData.size());
                result.put("data", transformedData);

                return request.createResponseBuilder(HttpStatus.OK)
                        .header("Content-Type", "application/json")
                        .body(objectMapper.writeValueAsString(result))
                        .build();
            }

            Map<String, String> response = new HashMap<>();
            response.put("message", "Data transformation service ready");
            response.put("usage", "Send POST with 'data' array to transform");

            return request.createResponseBuilder(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body(objectMapper.writeValueAsString(response))
                    .build();

        } catch (Exception e) {
            context.getLogger().severe("Error processing request: " + e.getMessage());

            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", e.getMessage());

            return request.createResponseBuilder(HttpStatus.INTERNAL_SERVER_ERROR)
                    .header("Content-Type", "application/json")
                    .body(objectMapper.writeValueAsString(errorResponse))
                    .build();
        }
    }
}
