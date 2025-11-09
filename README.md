# PythonEncrypt
 A neat single file directory encryptor.


# Requirements 
    python3.6>=

# Usage

    Ensure your files are backed up I am not responsible for data loss.

    Fast parallel processing (default)
    python3 encrypt.py -d ./MyDir -p "mypassword"

    Sequential processing for debugging
    python3 encrypt.py -d ./MyDir -p "mypassword" --sequential

    Limit parallel workers
    python3 encrypt.py -d ./MyDir -p "mypassword" --workers 4

    Fast mode (less secure but faster)
    python3 encrypt.py -d ./MyDir -p "mypassword" --fast


# Contributions

    If you would like to file an issue or submit a pull request you are more then welcome to.