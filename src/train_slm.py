import os
import argparse
import torch
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    BitsAndBytesConfig,
    DataCollatorForLanguageModeling,
    EarlyStoppingCallback
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from datasets import Dataset
import math

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", default="data/corpus/auth/corpus_full.txt")
    parser.add_argument("--output_dir", default="models/tinyllama_log_anomaly")
    parser.add_argument("--window_size", type=int, default=10) # 10 lines * ~57 tokens (p95) = ~570 tokens
    parser.add_argument("--test", action="store_true", help="Run a 100-step overfit test on 1000 sequences")
    return parser.parse_args()

def load_data(filepath, window_size, tokenizer, is_test=False):
    print(f"Loading data from {filepath}...")
    with open(filepath, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
        
    # Group into chronological windows
    sequences = []
    for i in range(0, len(lines), window_size):
        window = lines[i:i+window_size]
        if len(window) == window_size:
            sequences.append("\n".join(window))
            
    if is_test:
        sequences = sequences[:1000]
        
    print(f"Generated {len(sequences)} windowed sequences.")
    
    # Chronological Split: 80% train, 20% val
    split_idx = int(len(sequences) * 0.8)
    train_seqs = sequences[:split_idx]
    val_seqs = sequences[split_idx:]
    
    if is_test:
        # For an overfit test, train and val are the same to see loss drop
        val_seqs = train_seqs
        
    print("Tokenizing datasets...")
    def tokenize_fn(examples):
        return tokenizer(examples["text"], truncation=True, max_length=1024)
        
    train_ds = Dataset.from_dict({"text": train_seqs}).map(tokenize_fn, batched=True, remove_columns=["text"])
    val_ds = Dataset.from_dict({"text": val_seqs}).map(tokenize_fn, batched=True, remove_columns=["text"])
    
    return train_ds, val_ds

def main():
    args = parse_args()
    
    model_id = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
    
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        
    train_ds, val_ds = load_data(args.corpus, args.window_size, tokenizer, args.test)
    
    print("Loading model...")
    if torch.cuda.is_available():
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.float16
        )
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            quantization_config=bnb_config,
            device_map="auto"
        )
        model = prepare_model_for_kbit_training(model)
    else:
        print("WARNING: CUDA not available. Loading in fp32 on CPU for testing...")
        model = AutoModelForCausalLM.from_pretrained(model_id, device_map="cpu")
        
    print("Applying LoRA...")
    lora_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "v_proj"],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM"
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    
    # Training Arguments
    steps = 100 if args.test else -1
    epochs = 1 if args.test else 2
    
    training_args = TrainingArguments(
        output_dir=args.output_dir,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=4,
        optim="paged_adamw_32bit",
        save_steps=500,
        logging_steps=100 if not args.test else 10,
        learning_rate=2e-4,
        fp16=True,
        max_grad_norm=0.3,
        max_steps=steps,
        num_train_epochs=epochs,
        warmup_ratio=0.03,
        group_by_length=True,
        lr_scheduler_type="cosine",
        eval_strategy="steps",
        eval_steps=500 if not args.test else 20,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        report_to="none"
    )
    
    trainer = Trainer(
        model=model,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        args=training_args,
        data_collator=DataCollatorForLanguageModeling(tokenizer, mlm=False),
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)] if not args.test else []
    )
    
    print("Starting training...")
    trainer.train()
    
    if not args.test:
        print("Saving best model...")
        trainer.save_model(os.path.join(args.output_dir, "best_model"))
        tokenizer.save_pretrained(os.path.join(args.output_dir, "best_model"))
        
        # Log final perplexity on validation
        metrics = trainer.evaluate()
        try:
            perplexity = math.exp(metrics["eval_loss"])
            print(f"Final Validation Perplexity: {perplexity:.2f}")
        except OverflowError:
            print("Final Validation Perplexity: Infinity")

if __name__ == "__main__":
    main()
