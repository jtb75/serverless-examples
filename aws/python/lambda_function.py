import json
import pickle
import base64
from PIL import Image
import io

# SECURITY VULNERABILITY: Insecure Pickle Deserialization
# This function accepts user input and deserializes it using pickle,
# which can lead to arbitrary code execution if malicious data is provided.

def lambda_handler(event, context):
    """
    AWS Lambda function that processes image data and user preferences.

    VULNERABILITIES:
    1. Pickle deserialization of untrusted data (CRITICAL)
    2. Uses Pillow 8.0.0 which has CVE-2021-25287 (Buffer overflow)
    """

    try:
        # Extract user data from request
        body = json.loads(event.get('body', '{}'))

        # VULNERABILITY: Deserializing user-provided pickle data
        # An attacker can provide malicious serialized objects
        if 'user_prefs' in body:
            user_prefs_encoded = body['user_prefs']
            user_prefs_bytes = base64.b64decode(user_prefs_encoded)

            # DANGEROUS: pickle.loads() on untrusted data
            user_preferences = pickle.loads(user_prefs_bytes)
            print(f"User preferences loaded: {user_preferences}")

        # Process image if provided
        if 'image_data' in body:
            image_bytes = base64.b64decode(body['image_data'])
            image = Image.open(io.BytesIO(image_bytes))

            # Basic image processing
            width, height = image.size
            image_info = {
                'width': width,
                'height': height,
                'format': image.format,
                'mode': image.mode
            }

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Image processed successfully',
                    'image_info': image_info
                })
            }

        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Request processed'})
        }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
