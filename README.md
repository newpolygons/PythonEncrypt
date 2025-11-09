# PythonEncrypt
 A neat file directory encryptor, and single file decryptor.


# Requirements 
    python3.6>=

# Usage

    Ensure your files are backed up I am not responsible for data loss.


    (ENCRYPTING)

    Fast parallel processing (default)
    python3 encrypt.py -d ./MyDir -p "mypassword"

    Sequential processing for debugging
    python3 encrypt.py -d ./MyDir -p "mypassword" --sequential

    Limit parallel workers
    python3 encrypt.py -d ./MyDir -p "mypassword" --workers 4

    Fast mode (less secure but faster)
    python3 encrypt.py -d ./MyDir -p "mypassword" --fast

    (DECRYPTING)

    Decrypt from master JSON file (recommended)
    python3 decrypt.py -i encrypted_files/encrypted_files.json -p "mypassword" -o ./restored_files

    Decrypt from directory containing encrypted files
    python3 decrypt.py -i encrypted_files/ -p "mypassword" -o ./restored_files

    Decrypt a single encrypted file
    python3 decrypt.py -i encrypted_files/individual_files/myfile.txt.encrypted -p "mypassword" -o ./myfile.txt

    Sequential processing for debugging
    python3 decrypt.py -i encrypted_files/encrypted_files.json -p "mypassword" --sequential

    Limit parallel workers
    python3 decrypt.py -i encrypted_files/encrypted_files.json -p "mypassword" --workers 4


# Contributions

    If you would like to file an issue or submit a pull request you are more then welcome to.