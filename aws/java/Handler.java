package com.example.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * AWS Lambda function handler for data processing.
 *
 * VULNERABILITIES:
 * 1. Insecure deserialization using ObjectInputStream (CRITICAL)
 * 2. Uses log4j 2.14.1 which has CVE-2021-44228 (Log4Shell)
 */
public class Handler implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger logger = LogManager.getLogger(Handler.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public APIGatewayProxyResponseEvent handleRequest(APIGatewayProxyRequestEvent request, Context context) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of("Content-Type", "application/json"));

        try {
            String body = request.getBody();
            Map<String, Object> requestData = objectMapper.readValue(body, Map.class);

            // VULNERABILITY: Insecure deserialization
            // ObjectInputStream can execute arbitrary code when deserializing malicious objects
            if (requestData.containsKey("serializedData")) {
                String serializedDataBase64 = (String) requestData.get("serializedData");
                byte[] serializedData = Base64.getDecoder().decode(serializedDataBase64);

                // DANGEROUS: Deserializing untrusted data
                try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedData))) {
                    Object deserializedObject = ois.readObject();
                    logger.info("Deserialized object: {}", deserializedObject);
                }
            }

            // Log user input (vulnerable to Log4Shell if malicious JNDI lookup string provided)
            String userInput = (String) requestData.getOrDefault("message", "No message");
            logger.info("Processing user message: {}", userInput);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("message", "Data processed successfully");
            responseBody.put("input", userInput);

            response.setStatusCode(200);
            response.setBody(objectMapper.writeValueAsString(responseBody));

        } catch (Exception e) {
            logger.error("Error processing request", e);
            response.setStatusCode(500);
            response.setBody("{\"error\": \"" + e.getMessage() + "\"}");
        }

        return response;
    }
}
