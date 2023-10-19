import os
import zlib
import chardet
import magic
import pygments
import pygments.util
import codecs  # Import codecs for base64 decoding
from pygments.lexers import guess_lexer_for_filename
from pygments.lexers import guess_lexer
from pygments.lexers import get_lexer_for_filename

def identify_programming_language(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read(1024)

        programming_language = "Unknown"

        try:
            # Try to detect the programming language based on the file content
            lexer = guess_lexer(data)
            programming_language = lexer.name
        except pygments.util.ClassNotFound:
            # If it can't be determined from the content, try using the file extension
            programming_language = get_lexer_for_filename(file_path).name

        return programming_language
    except Exception as e:
        return f"Error: {str(e)}"

def detect_encoding(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        result = chardet.detect(data)
        return result['encoding']
    except Exception as e:
        return f"Error: {str(e)}"

def detect_compression(file_path):
    with open(file_path, 'rb') as f:
        data = f.read(1024)

    try:
        if zlib.decompress(data, wbits=zlib.MAX_WBITS, bufsize=zlib.MAX_WBITS):
            return "zlib (gzip) compression"
    except zlib.error as e:
        return "No valid zlib compression detected"

    return "No compression detected"

def detect_obfuscation(code_bytes):
    try:
        decoded_bytes = codecs.decode(code_bytes, 'base64')
        return "Base64 encoding detected"
    except Exception as e:
        return "No obfuscation detected"

def deobfuscate_code(code_bytes, obfuscation_type):
    if obfuscation_type == "Base64 encoding detected":
        try:
            decoded_bytes = codecs.decode(code_bytes, 'base64')
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"Error decoding Base64: {str(e)}"

    # Add more deobfuscation methods as needed

    # If obfuscation type is not recognized
    return "Unable to deobfuscate"

def main():
    file_path = input("Enter the path to the file: ")
    if not os.path.isfile(file_path):
        print("File not found.")
        return

    mime = magic.Magic()
    file_type = mime.from_file(file_path)
    programming_language = identify_programming_language(file_path)
    encoding = detect_encoding(file_path)
    compression = detect_compression(file_path)

    with open(file_path, 'rb') as f:
        code_bytes = f.read()

    obfuscation_type = detect_obfuscation(code_bytes)
    deobfuscated_code = deobfuscate_code(code_bytes, obfuscation_type)

    print(f"File Type: {file_type}")
    print(f"Programming Language: {programming_language}")
    print(f"Encoding: {encoding}")
    print(f"Compression: {compression}")
    print(f"Obfuscation: {obfuscation_type}")
    print(f"Deobfuscated Code:\n{deobfuscated_code}")

if __name__ == "__main__":
    main()
