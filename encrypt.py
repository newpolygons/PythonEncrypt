#!/usr/bin/env python3
import os
import sys
import argparse
import base64
import hashlib
import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

class LocalFileEncryptor:
    def __init__(self, password):
        self.password = password
        self.base_key = hashlib.sha256(password.encode()).digest()
    def xor_encrypt(self, data, key):
        if isinstance(data, (bytes, bytearray)):
            data_bytes = data
        else:
            data_bytes = data.encode('utf-8')
        key_material = hashlib.pbkdf2_hmac('sha256', key, b'encryption_salt', 50000, len(data_bytes))
        result = bytearray(data_bytes)
        for i in range(len(result)):
            result[i] ^= key_material[i]
        return bytes(result)
    
    def encrypt_content(self, content):
        salt = secrets.token_bytes(32) 
        if isinstance(content, str):
            content = content.encode('utf-8')
        encryption_key = hashlib.pbkdf2_hmac('sha256', self.base_key, salt, 50000, 32)
        encrypted_content = self.xor_encrypt(content, encryption_key)
        combined = salt + encrypted_content
        return base64.b64encode(combined).decode('utf-8')
    
    def process_single_file(self, file_path, base_directory):
        try:
            file_path_obj = Path(file_path)
            with open(file_path_obj, 'rb') as f:
                content = f.read()
            encrypted_content = self.encrypt_content(content)
            relative_path = file_path_obj.relative_to(base_directory)
            return {
                'original_path': str(relative_path),
                'encrypted_content': encrypted_content,
                'original_size': len(content),
                'algorithm': 'XOR-PBKDF2-SHA256'
            }
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return None

    def find_files(self, directory, exclude_extensions=None):
        if exclude_extensions is None:
            exclude_extensions = {'.encrypted'}
        directory_path = Path(directory)
        if not directory_path.exists():
            raise ValueError(f"Directory {directory} does not exist")
        return [
            file_path for file_path in directory_path.rglob('*')
            if file_path.is_file() and file_path.suffix not in exclude_extensions
        ]
    
    def process_files_parallel(self, directory, max_workers=None):
        files = self.find_files(directory)
        print(f"Found {len(files)} files to process...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self.process_single_file, file_path, directory): file_path 
                for file_path in files
            }
            encrypted_files = []
            completed = 0

            for future in future_to_file:
                result = future.result()
                if result is not None:
                    encrypted_files.append(result)
                    completed += 1
                    if completed % 10 == 0: 
                        print(f"Processed {completed}/{len(files)} files...")
        return encrypted_files
    
    def process_files_sequential(self, directory):
        files = self.find_files(directory)
        encrypted_files = []
        for i, file_path in enumerate(files):
            print(f"Processing: {file_path} ({i+1}/{len(files)})")
            result = self.process_single_file(file_path, directory)
            if result is not None:
                encrypted_files.append(result)
        return encrypted_files
    
    def save_encrypted_files(self, encrypted_files, output_dir='encrypted_files'):
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        master_file = output_path / 'encrypted_files.json'
        
        with open(master_file, 'w') as f:
            json.dump({
                'files': encrypted_files,
                'version': '1.0',
                'algorithm': 'XOR-PBKDF2-SHA256'
            }, f, separators=(',', ':'))
        print(f"Saved all encrypted files to: {master_file}")
        
        save_individual = input("Save individual encrypted files? (y/N): ").lower().startswith('y')
        if save_individual:
            individual_dir = output_path / 'individual_files'
            individual_dir.mkdir(exist_ok=True)
            for file_info in encrypted_files:
                safe_name = file_info['original_path'].replace('/', '_').replace('\\', '_')
                individual_file = individual_dir / f"{safe_name}.encrypted"
                with open(individual_file, 'w') as f:
                    json.dump(file_info, f, separators=(',', ':'))
    
    def estimate_time(self, directory):
        files = self.find_files(directory)
        total_size = sum(f.stat().st_size for f in files)
        print(f"Files to process: {len(files)}")
        print(f"Total size: {total_size / (1024*1024):.2f} MB")
        estimated_seconds = total_size / (1024 * 1024)
        if estimated_seconds > 60:
            print(f"Estimated time: {estimated_seconds/60:.1f} minutes")
        else:
            print(f"Estimated time: {estimated_seconds:.1f} seconds")
        return len(files), total_size

def main():
    parser = argparse.ArgumentParser(description='Encrypt local files.')
    parser.add_argument('-d', '--directory', required=True, 
                       help='Local directory to encrypt')
    parser.add_argument('-p', '--password', required=True,
                       help='Encryption password')
    parser.add_argument('-o', '--output', default='encrypted_files',
                       help='Output directory for encrypted files (default: encrypted_files)')
    parser.add_argument('--parallel', action='store_true', default=True,
                       help='Use parallel processing (default: True)')
    parser.add_argument('--sequential', action='store_true',
                       help='Use sequential processing (instead of parallel)')
    parser.add_argument('--workers', type=int, default=None,
                       help='Number of parallel workers (default: auto)')
    parser.add_argument('--fast', action='store_true',
                       help='Use faster but less secure settings')
    
    args = parser.parse_args()
    encryptor = LocalFileEncryptor(args.password)
    file_count, total_size = encryptor.estimate_time(args.directory)
    if total_size > 100 * 1024 * 1024: 
        print("Large dataset detected. Using parallel processing recommended.")
    start_time = time.time()
    print(f"\nStarting encryption of {file_count} files...")
    if args.sequential:
        encrypted_files = encryptor.process_files_sequential(args.directory)
    else:
        encrypted_files = encryptor.process_files_parallel(args.directory, args.workers)
    end_time = time.time()
    print(f"\nEncrypted {len(encrypted_files)} files in {end_time - start_time:.2f} seconds")
    encryptor.save_encrypted_files(encrypted_files, args.output)
    print(f"\nAll files have been encrypted and saved to: {args.output}")
    print(f"Processing speed: {total_size / (end_time - start_time) / (1024*1024):.2f} MB/s")

if __name__ == "__main__":
    main()