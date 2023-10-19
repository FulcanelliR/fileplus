import os
import zlib
import chardet
import magic
import pygments
import pygments.util
import codecs
from urllib.parse import unquote  # Import for URLdecode
from pygments.lexers import guess_lexer_for_filename, guess_lexer, get_lexer_for_filename

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
        codecs.decode(code_bytes, 'base64')
        return "Base64 possible encoding detected"
    except:
        pass

    try:
        if all([c in '01' for c in code_bytes.decode('utf-8', errors='ignore')]):
            return "Binary possible encoding detected"
    except:
        pass

    try:
        int(code_bytes.decode('utf-8', errors='ignore'), 16)
        return "Hex possible encoding detected"
    except:
        pass

    try:
        unquote(code_bytes.decode('utf-8', errors='ignore'))
        return "URL possible encoding detected"
    except:
        pass

    return "No obfuscation detected"

def deobfuscate_code(code_bytes, obfuscation_type):
    decoded_str = ""
    try:
        if obfuscation_type == "Base64 possible encoding detected":
            decoded_str = codecs.decode(code_bytes, 'base64').decode('utf-8', errors='ignore')
        elif obfuscation_type == "Binary possible encoding detected":
            decoded_str = ''.join([chr(int(code_bytes[i:i+8].decode('utf-8'), 2)) for i in range(0, len(code_bytes), 8)])
        elif obfuscation_type == "Hex possible encoding detected":
            decoded_str = bytes.fromhex(code_bytes.decode('utf-8', errors='ignore')).decode('utf-8', errors='ignore')
        elif obfuscation_type == "URL possible encoding detected":
            decoded_str = unquote(code_bytes.decode('utf-8', errors='ignore'))
        return decoded_str
    except Exception as e:
        return f"Error decoding possible {obfuscation_type}: {str(e)}"

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
