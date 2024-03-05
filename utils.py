from dotenv import load_dotenv
import boto3
import os
import zipfile
import shutil
import ezkl


# Load environment variables from .env file
load_dotenv()


witness_path = os.path.join('witness.json')
# data_path = os.path.join('input.json')

sol_code_path = os.path.join('Verifier.sol')
abi_path = os.path.join('Verifier.abi')


# Function to set up S3 client
def setup_s3_client():
    access_key = os.getenv('S3_ACCESS_KEY')
    secret_key = os.getenv('S3_SECRET_KEY')
    region = os.getenv('S3_REGION')

    if access_key and secret_key and region:
        s3 = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        return s3
    else:
        raise ValueError("S3 credentials are not set in the .env file")


# Function to download file from S3 bucket
def download_from_s3(bucket_name, file_key, local_path):
    s3 = setup_s3_client()
    try:
        s3.download_file(bucket_name, file_key, local_path)
        return True
    except Exception as e:
        print(f"Error downloading file from S3: {e}")
        return False


# Function to upload file to S3 bucket
def upload_to_s3(file_paths, bucket_name, file_key):
    s3 = setup_s3_client()
    try:
        for file_path in file_paths:
            s3.upload_file(file_path, bucket_name, file_key + '/'  + file_path)
        return True
    except Exception as e:
        print(f"Error uploading file to S3: {e}")
        return False


# Function to unzip file
def unzip_file(zip_file, output_dir):
    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(output_dir)


def zip_model_assets(zip_file_name, local_model_assets_folder):
    # Move Verifier.sol and Verifier.abi to model_assets folder
    shutil.move('Verifier.sol', f'{local_model_assets_folder}/Verifier.sol')
    shutil.move('Verifier.abi', f'{local_model_assets_folder}/Verifier.abi')

    # Create a zip file of the model_assets folder
    with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(local_model_assets_folder):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), local_model_assets_folder))

    return True


def generate_verifier(local_model_assets_folder, optimization="resources", max_logrows=17, scales=[7]):
    model_path = os.path.join(f'{local_model_assets_folder}/model.onnx')
    settings_path = os.path.join(f'{local_model_assets_folder}/settings.json')
    cal_data_path = os.path.join(f'{local_model_assets_folder}/cal_data.json')

    compiled_model_path = os.path.join(f'{local_model_assets_folder}/network.ezkl')

    pk_path = os.path.join(f'{local_model_assets_folder}/test.pk')
    vk_path = os.path.join(f'{local_model_assets_folder}/test.vk')

    res = ezkl.gen_settings(model_path, settings_path)
    if not res:
        return False
    
    res = ezkl.calibrate_settings(cal_data_path, model_path, settings_path, optimization, max_logrows = max_logrows, scales = scales)

    res = ezkl.compile_circuit(model_path, compiled_model_path, settings_path)
    if not res:
        return False
    
    res = ezkl.get_srs( settings_path)

    res = ezkl.setup(
            compiled_model_path,
            vk_path,
            pk_path,
        )
    if not res:
        return False

    res = ezkl.create_evm_verifier(
        vk_path,

        settings_path,
        sol_code_path,
        abi_path
    )
    if not res:
        return False
    
    return True