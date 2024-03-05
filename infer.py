import subprocess
import os

access_key = os.getenv('S3_ACCESS_KEY')
secret_key = os.getenv('S3_SECRET_KEY')

def perform_inference(image_name, input_data, user_id, model_id, image_id):
    # Execute inference inside the Docker container
    command = [
        'docker', 'run',
        '--gpus', 'all',
        '-e', f'AWS_ACCESS_KEY_ID={access_key}',
        '-e', f'AWS_SECRET_ACCESS_KEY={secret_key}',
        image_name,
        '--input', input_data,
        '--user_id', user_id,
        '--model_id', model_id,
        '--image_id', image_id
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    # Check if there's any error during inference
    if process.returncode != 0:
        error_message = stderr.decode().strip()
        return {'error': error_message}

    # Return the output
    output = stdout.decode().strip()
    return {'output': output}

