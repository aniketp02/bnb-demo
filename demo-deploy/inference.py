import torch
from torch import autocast
from diffusers import StableDiffusionPipeline
import argparse
import ezkl
import boto3
import os

data_path = os.path.join('cal_data.json')
compiled_model_path = os.path.join('network.ezkl')
pk_path = os.path.join('test.pk')
vk_path = os.path.join('test.vk')
settings_path = os.path.join('settings.json')

# AWS credentials from environment variables
aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
s3_bucket_name = 'bnb-hackathon'  # Replace with your S3 bucket name


def perform_inference(input_data, user_id, model_id, image_id):
    proof_path = os.path.join(f'proof_{image_id}.json')
    s3_upload_file_key = f'{user_id}/{model_id}'

    # Generate Wiafu Image
    pipe = StableDiffusionPipeline.from_pretrained(
                'hakurei/waifu-diffusion',
                torch_dtype=torch.float32
            ).to('cuda')

    with autocast("cuda"):
        image = pipe([input_data], guidance_scale=6)["images"][0]

    image.save(f'{image_id}.png')
    print("\n\n Image generated successfully!\n\n")

    # Generate the Witness for the proof
    witness_path = os.path.join('witness.json')

    res = ezkl.gen_witness(data_path, compiled_model_path, witness_path)
    assert os.path.isfile(witness_path)

    res = ezkl.get_srs( settings_path)

    # Generate the proof
    proof = ezkl.prove(
            witness_path,
            compiled_model_path,
            pk_path,
            proof_path,
            "single",
        )
    assert os.path.isfile(proof_path)

    print(proof)

    # Upload files to S3
    upload_files_to_s3([f'proof_{image_id}.json', f'{image_id}.png'], s3_upload_file_key)
    print("\n Uploaded files to S3 \n")

    return True


def upload_files_to_s3(files, file_key):
    s3 = boto3.client(
        's3',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    # Upload each file to S3
    for file in files:
        s3.upload_file(file, s3_bucket_name, file_key + '/'  + file)
        print(f"Uploaded {file} to S3 bucket {s3_bucket_name}")


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Perform inference using a pre-trained model.")
    parser.add_argument("--user_id", type=str, help="User id to upload the artifacts to S3")
    parser.add_argument("--model_id", type=str, help="Model id to upload the artifacts to S3")
    parser.add_argument("--image_id", type=str, help="Image id to upload the artifacts to S3")
    parser.add_argument("--input", type=str, help="Input data for inference")
    args = parser.parse_args()

    # Check if input is provided
    if args.input is None:
        parser.error("Please provide input data using --input flag.")

    # Perform inference
    result = perform_inference(args.input, args.user_id, args.model_id, args.image_id)
    print("Predicted class:", result)
    return result

if __name__ == "__main__":
    main()