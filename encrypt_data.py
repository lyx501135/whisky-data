#!/usr/bin/env python3
"""
Encrypt JSON data files for Whisky Notebook app.

This script encrypts JSON files using AES-256-CBC encryption with the same
key and IV used by the Flutter app, ensuring proper compatibility.

Usage:
    python3 encrypt_data.py

Requirements:
    pip3 install pycryptodome
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
import os
import sys

# IMPORTANT: These must match the values in lib/services/data_sync_service.dart
KEY = b'WhiskyNB2024Key!WhiskyNB2024Key!'  # 32 bytes for AES-256
IV = b'WhiskyNotebookIV'  # 16 bytes


def encrypt_file(input_file, output_file):
    """Encrypt JSON file using AES-256-CBC and base64 encode."""
    print(f'🔐 Encrypting {input_file}...')
    
    if not os.path.exists(input_file):
        print(f'❌ Error: {input_file} not found')
        return False
    
    try:
        # Read the JSON file
        with open(input_file, 'r', encoding='utf-8') as f:
            plaintext = f.read()
        
        # Validate JSON
        json.loads(plaintext)
        
        # Create AES cipher
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        
        # Pad the plaintext to be multiple of 16 bytes (AES block size)
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        
        # Encrypt
        encrypted_data = cipher.encrypt(padded_data)
        
        # Base64 encode for storage
        encoded = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Write to output file
        with open(output_file, 'w') as f:
            f.write(encoded)
        
        print(f'✅ Created {output_file} ({len(encoded)} bytes)')
        return True
        
    except json.JSONDecodeError as e:
        print(f'❌ Invalid JSON in {input_file}: {e}')
        return False
    except Exception as e:
        print(f'❌ Error encrypting {input_file}: {e}')
        return False


def decrypt_file(input_file):
    """Decrypt and verify an encrypted file."""
    try:
        with open(input_file, 'r') as f:
            encrypted_data = base64.b64decode(f.read())
        
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted_data = unpad(decrypted_padded, AES.block_size).decode('utf-8')
        
        # Validate JSON
        json.loads(decrypted_data)
        return True
    except Exception as e:
        print(f'❌ Error decrypting {input_file}: {e}')
        return False


def main():
    """Encrypt all JSON data files."""
    print('🔐 Whisky Notebook Data Encryptor')
    print('=' * 50)
    
    files = ['countries.json', 'regions.json', 'distilleries.json', 'whiskies.json']
    
    success_count = 0
    for filename in files:
        if encrypt_file(filename, f'{filename}.enc'):
            # Verify the encrypted file can be decrypted
            if decrypt_file(f'{filename}.enc'):
                print(f'✓ Verified {filename}.enc can be decrypted')
                success_count += 1
            else:
                print(f'✗ Failed to verify {filename}.enc')
        print()
    
    print('=' * 50)
    if success_count == len(files):
        print(f'🎉 All {len(files)} files encrypted successfully!')
        print('\nNext steps:')
        print('  1. git add *.enc')
        print('  2. git commit -m "Update encrypted data files"')
        print('  3. git push')
        return 0
    else:
        print(f'⚠️  Only {success_count}/{len(files)} files encrypted successfully')
        return 1


if __name__ == '__main__':
    sys.exit(main())

