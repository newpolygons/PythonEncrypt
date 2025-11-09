#!/usr/bin/env python3
import os
import sys
import argparse
import base64
import hashlib
import json
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

class LocalFileDecryptor:
    def __init__(self, password):
        self.password = password
        self.base_key = hashlib.sha256(password.encode()).digest()
    
    def xor_decrypt(self, data, key):
        if isinstance(data, (bytes, bytearray)):
            data_bytes = data
        else:
            data_bytes = data.encode('utf-8')
        key_material = hashlib.pbkdf2_hmac('sha256', key, b'encryption_salt', 50000, len(data_bytes))
        result = bytearray(data_bytes)
        for i in range(len(result)):
            result[i] ^= key_material[i]
        return bytes(result)
    
    def decrypt_content(self, encrypted_content_b64):
        try:
            combined = base64.b64decode(encrypted_content_b64)
            salt = combined[:16]
            encrypted_content = combined[16:]
            encryption_key = hashlib.pbkdf2_hmac('sha256', self.base_key, salt, 50000, 32)
            decrypted_content = self.xor_decrypt(encrypted_content, encryption_key)
            return decrypted_content
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def load_encrypted_files(self, input_path):
        input_path = Path(input_path)
        
        if input_path.is_file():
            with open(input_path, 'r') as f:
                data = json.load(f)
            
            if 'files' in data:
                return data['files']
            else:
                return [data]
        elif input_path.is_dir():
            encrypted_files = []
            master_file = input_path / 'encrypted_files.json'
            if master_file.exists():
                with open(master_file, 'r') as f:
                    data = json.load(f)
                return data['files']
            for file_path in input_path.rglob('*.encrypted'):
                with open(file_path, 'r') as f:
                    file_data = json.load(f)
                encrypted_files.append(file_data)
            individual_dir = input_path / 'individual_files'
            if individual_dir.exists():
                for file_path in individual_dir.rglob('*.encrypted'):
                    with open(file_path, 'r') as f:
                        file_data = json.load(f)
                    encrypted_files.append(file_data)
            return encrypted_files
        else:
            raise ValueError(f"Input path {input_path} does not exist")
    
    def process_single_file(self, file_info, output_directory):
        try:
            original_path = file_info['original_path']
            encrypted_content = file_info['encrypted_content']
            decrypted_content = self.decrypt_content(encrypted_content)
            output_path = Path(output_directory) / original_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(decrypted_content)
            return {
                'original_path': original_path,
                'output_path': str(output_path),
                'success': True
            }
        except Exception as e:
            print(f"Error decrypting {file_info.get('original_path', 'unknown')}: {e}")
            return {
                'original_path': file_info.get('original_path', 'unknown'),
                'error': str(e),
                'success': False
            }
    
    def decrypt_files_parallel(self, encrypted_files, output_directory, max_workers=None):
        print(f"Decrypting {len(encrypted_files)} files...")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self.process_single_file, file_info, output_directory): file_info 
                for file_info in encrypted_files
            }
            results = []
            completed = 0
            for future in future_to_file:
                result = future.result()
                results.append(result)
                completed += 1
                if completed % 10 == 0: 
                    print(f"Decrypted {completed}/{len(encrypted_files)} files...")
        return results
    
    def decrypt_files_sequential(self, encrypted_files, output_directory):
        results = []
        for i, file_info in enumerate(encrypted_files):
            original_path = file_info['original_path']
            print(f"Decrypting: {original_path} ({i+1}/{len(encrypted_files)})")
            
            result = self.process_single_file(file_info, output_directory)
            results.append(result)
        
        return results
    
    def verify_decryption(self, results):
        successful = [r for r in results if r['success']]
        failed = [r for r in results if not r['success']]
        print(f"\nDecryption Summary:")
        print(f"Successful: {len(successful)} files")
        print(f"Failed: {len(failed)} files")
        if failed:
            print(f"\nFailed files:")
            for fail in failed:
                print(f"  - {fail['original_path']}: {fail['error']}")
        return len(successful), len(failed)

def main():
    parser = argparse.ArgumentParser(description='Decrypt files encrypted with encrypt.py')
    parser.add_argument('-i', '--input', required=True, 
                       help='Input path (encrypted master JSON, individual file, or directory)')
    parser.add_argument('-p', '--password', required=True,
                       help='Decryption password')
    parser.add_argument('-o', '--output', default='decrypted_files',
                       help='Output directory for decrypted files (default: decrypted_files)')
    parser.add_argument('--parallel', action='store_true', default=True,
                       help='Use parallel processing (default: True)')
    parser.add_argument('--sequential', action='store_true',
                       help='Use sequential processing (instead of parallel)')
    parser.add_argument('--workers', type=int, default=None,
                       help='Number of parallel workers (default: auto)')
    args = parser.parse_args()
    decryptor = LocalFileDecryptor(args.password)
    print(f"Loading encrypted files from: {args.input}")
    try:
        encrypted_files = decryptor.load_encrypted_files(args.input)
        print(f"Loaded {len(encrypted_files)} encrypted files")
    except Exception as e:
        print(f"Error loading encrypted files: {e}")
        sys.exit(1)
    output_path = Path(args.output)
    output_path.mkdir(parents=True, exist_ok=True)
    start_time = time.time()
    print(f"\nStarting decryption to: {args.output}")
    if args.sequential:
        results = decryptor.decrypt_files_sequential(encrypted_files, args.output)
    else:
        results = decryptor.decrypt_files_parallel(encrypted_files, args.output, args.workers)
    end_time = time.time()
    successful, failed = decryptor.verify_decryption(results)
    print(f"\nDecryption completed in {end_time - start_time:.2f} seconds")
    print(f"Files saved to: {args.output}")
    if failed > 0:
        print(f"\nWarning: {failed} files failed to decrypt. Check password and file integrity.")
        sys.exit(1)

def decrypt_single_file():
    parser = argparse.ArgumentParser(description='Decrypt a single encrypted file')
    parser.add_argument('-i', '--input', required=True, 
                       help='Input encrypted file')
    parser.add_argument('-p', '--password', required=True,
                       help='Decryption password')
    parser.add_argument('-o', '--output', 
                       help='Output file path (optional)')
    args = parser.parse_args()
    decryptor = LocalFileDecryptor(args.password)
    
    try:
        with open(args.input, 'r') as f:
            file_data = json.load(f)
        decrypted_content = decryptor.decrypt_content(file_data['encrypted_content'])
        if args.output:
            output_path = args.output
        else:
            original_name = file_data.get('original_path', 'decrypted_file')
            output_path = f"decrypted_{original_name}"
        with open(output_path, 'wb') as f:
            f.write(decrypted_content)
        print(f"Successfully decrypted to: {output_path}")
    except Exception as e:
        print(f"Decryption failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()