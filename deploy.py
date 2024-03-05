import os
import zipfile
import subprocess

DOCKERFILE_CONTENT = f'''
    FROM python:3.8-slim
    
    # Set working directory
    WORKDIR /app
    
    # Copy model assets
    COPY . /app
    
    # Install dependencies
    RUN pip install --no-cache-dir -r requirements.txt
    
    # Command to run inference
    ENTRYPOINT ["python", "inference.py"]
    '''

def start_docker_container(zip_file_path, user_id, model_id):

    image_name = f'{user_id}_{model_id}_inference'

    # Step 1: Create a temporary directory to extract the model assets
    temp_dir = '/tmp'
    work_dir = os.path.join(temp_dir, 'model_assets')
    os.makedirs(temp_dir, exist_ok=True)

    # Step 2: Extract the model assets from the zip file
    with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
        zip_ref.extractall(temp_dir)

    # Step 3: Create a Dockerfile
    dockerfile_path = os.path.join(work_dir, 'Dockerfile')
    with open(dockerfile_path, 'w') as dockerfile:
        dockerfile.write(DOCKERFILE_CONTENT)
    
    # Step 4: Build Docker image
    build_process = subprocess.run(['docker', 'build', '-t', image_name, work_dir], capture_output=True)
    if build_process.returncode != 0:
        # Image build failed
        print("Image build failed:", build_process.stderr.decode())
        return False
    
    # Cleanup: Remove temporary directory and Dockerfile
    # shutil.rmtree(temp_dir)
    return True
