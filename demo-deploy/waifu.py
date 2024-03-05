import torch
from torch import autocast
from diffusers import StableDiffusionPipeline

pipe = StableDiffusionPipeline.from_pretrained(
    'hakurei/waifu-diffusion',
    torch_dtype=torch.float32
).to('cuda')

prompt = "blue eyes, short hair"
with autocast("cuda"):
    image = pipe([prompt], guidance_scale=6)["images"][0]

image.save("test.png")