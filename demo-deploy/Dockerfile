FROM nvidia/cuda:11.2.2-cudnn8-runtime-ubuntu20.04
    
WORKDIR /app

COPY . /app

# Python and required dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.8 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir -r requirements.txt

# Command to run inference
ENTRYPOINT ["python3", "inference.py"]
