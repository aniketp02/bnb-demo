from flask import Flask, request, jsonify
import utils
import deploy
import infer

app = Flask(__name__)

@app.route('/load_model', methods=['POST'])
def load_model():
    data = request.json
    model_assets_path = data.get('model_assets')
    bucket = data.get('s3_bucket')
    max_logrows = data.get('max_logrows')
    scales = data.get('scales')
    optimization = data.get('optimization_target')
    user_id = data.get('user_id')
    model_id = data.get('model_id')

    s3_upload_file_key = f'{user_id}/{model_id}'
    local_model_assets_folder = f'model_assets_{user_id}_{model_id}'
    local_model_zip_file = local_model_assets_folder + '.zip'

    # Download model assets from S3
    if model_assets_path:
        if not utils.download_from_s3(bucket, model_assets_path, local_model_zip_file):
            return jsonify({'message': 'Failed to download model assets from S3'}), 500

        # Unzip model assets
        utils.unzip_file(local_model_zip_file, local_model_assets_folder)

    res = utils.generate_verifier(local_model_assets_folder=local_model_assets_folder,
                                  optimization=optimization, 
                                  max_logrows=max_logrows, 
                                  scales=scales
                                )
    
    if not res:
        return jsonify({'message': 'Failed to generate the Verifier!'}), 500

    if not utils.upload_to_s3(['Verifier.sol', 'Verifier.abi'], bucket, s3_upload_file_key ):
        return jsonify({'message': 'Failed to upload the generated Verifier!'}), 500

    return jsonify({'message': 'Verifier Generated successfully'}), 200


@app.route('/store_model_assets', methods=['POST'])
def store_model_assets():
    data = request.json
    user_id = data.get('user_id')
    model_id = data.get('model_id')
    bucket = data.get('s3_bucket')

    local_model_assets_folder = f'model_assets_{user_id}_{model_id}'
    model_zip_path = f'model_assets.zip'
    s3_upload_file_key = f'{user_id}/{model_id}'

    if not utils.zip_model_assets(model_zip_path, local_model_assets_folder):
        return jsonify({'message': 'Error getting model assets from the server'}), 500
    
    if not utils.upload_to_s3([model_zip_path], bucket, s3_upload_file_key):
        return jsonify({'message': 'Error uploading model assets to s3 storage'}), 500

    #TODO: Clear all the files from the server!
    return jsonify({'message': 'Models assets stored successfully!'}), 200


@app.route('/deploy', methods=['POST'])
def deploy_docker():
    data = request.json
    user_id = data.get('user_id')
    model_id = data.get('model_id')
    bucket = data.get('s3_bucket')

    model_zip_path = f'model_assets.zip'
    s3_model_assets_path = f'{user_id}/{model_id}/{model_zip_path}'

    # Download model assets from S3
    if not utils.download_from_s3(bucket, s3_model_assets_path, model_zip_path):
        return jsonify({'message': 'Failed to download model assets from S3'}), 500

    res = deploy.start_docker_container(model_zip_path, user_id, model_id)
    if not res:
        return jsonify({'message': 'Failed to deploy the model!'}), 500

    return jsonify({'message': 'Model deployed successfully!'}), 200


@app.route('/infer', methods=['POST'])
def infer_image():
    data = request.json
    user_id = data.get('user_id')
    model_id = data.get('model_id')
    bucket = data.get('s3_bucket')
    input = data.get('input')
    image_id = data.get('image_id')

    # print(type(input), input)
    image_name = f'{user_id}_{model_id}_inference' 
    print("generating inference")
    res = None
    res = infer.perform_inference(image_name=image_name, 
                                  input_data=input, 
                                  user_id=user_id, 
                                  model_id=model_id, 
                                  image_id=image_id
                                )
    print(res)
    if res == None:
        return jsonify({'message': 'Error generating Inference!'}), 500
    return jsonify({'message': 'Inference generated successfully!'}), 200


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
