import torch
from torch.autograd import Variable
from model import Model


def perform_inference(input_data):
    # Initialize Model
    model = Model()

    # Load trained model weights
    model.load_state_dict(torch.load('model.pt'))
    model.eval()  # Set the model to evaluation mode

    # Prepare input data for inference
    input_tensor = Variable(torch.Tensor(input_data).float())

    # Perform inference
    with torch.no_grad():
        output = model(input_tensor)
        predicted_class = torch.argmax(output).item()

    # Mapping predicted class index to class name
    class_names = ['setosa', 'versicolor', 'virginica']
    
    if predicted_class > 2:
        return "Unknown"
    
    predicted_class_name = class_names[predicted_class]
    return predicted_class_name