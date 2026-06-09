import os
import argparse
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base_model", default="TinyLlama/TinyLlama-1.1B-Chat-v1.0")
    parser.add_argument("--lora_model", default="models/tinyllama_log_anomaly/best_model")
    parser.add_argument("--output_dir", default="models/tinyllama_log_anomaly/merged_model")
    return parser.parse_args()

def main():
    args = parse_args()
    
    print(f"Loading base model: {args.base_model}...")
    # Load base model in fp16 to ensure clean merging without quantization artifacts
    base_model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.float16,
        low_cpu_mem_usage=True,
        device_map="cpu"
    )
    
    print(f"Loading LoRA weights from: {args.lora_model}...")
    model = PeftModel.from_pretrained(base_model, args.lora_model)
    
    print("Merging LoRA weights with base model...")
    model = model.merge_and_unload()
    
    print(f"Saving merged model to {args.output_dir}...")
    os.makedirs(args.output_dir, exist_ok=True)
    model.save_pretrained(args.output_dir)
    
    print("Saving tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(args.lora_model)
    tokenizer.save_pretrained(args.output_dir)
    
    print("\n--- Model Merging Complete ---")
    print(f"Your merged model is at: {args.output_dir}")
    print("To convert to GGUF for Raspberry Pi, use llama.cpp:")
    print(f"  python /path/to/llama.cpp/convert.py {args.output_dir} --outfile {args.output_dir}/tinyllama_anomaly.gguf --outtype q4_k_m")

if __name__ == "__main__":
    main()
