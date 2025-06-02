#!/usr/bin/env python3

import argparse
import base64
import hashlib
import os
import random
import re
import string

import bcrypt


def generate_password(length=12, special=True):
    if length < 4:
        return "Password length should be at least 4"

    characters = string.ascii_letters + string.digits
    if special:
        characters += '!@#$%^&*(),.?":{}|<>'

    while True:
        password = "".join(random.choice(characters) for _ in range(length))
        if (
            re.search(r"[A-Z]", password)
            and re.search(r"[a-z]", password)
            and re.search(r"\d", password)
            and (not special or re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
        ):
            return password


def check_password_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None

    if length_error:
        return "Password too short. Minimum 8 characters required."
    if digit_error:
        return "Password must contain at least one digit."
    if uppercase_error:
        return "Password must contain at least one uppercase letter."
    if lowercase_error:
        return "Password must contain at least one lowercase letter."
    if symbol_error:
        return "Password must contain at least one special character."

    return "Strong password ✅"


def generate_sha256(text):
    sha = hashlib.sha256()
    sha.update(text.encode("utf-8"))
    return sha.hexdigest()


def hash_file_sha256(filepath):
    if not os.path.isfile(filepath):
        return f"File not found: {filepath}"
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception as e:
        return f"Error reading file: {e}"


def caesar_cipher(mode, message, shift):
    result = []
    shift = shift % 26

    for char in message:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            if mode == "encrypt":
                shifted = (ord(char) - base + shift) % 26 + base
            else:
                shifted = (ord(char) - base - shift) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(char)
    return "".join(result)


def xor_cipher(message, key):
    result = []
    key_length = len(key)
    for i, char in enumerate(message):
        result.append(chr(ord(char) ^ ord(key[i % key_length])))
    return "".join(result)


def base64_convert(mode, text):
    if mode == "encode":
        encoded_bytes = base64.b64encode(text.encode("utf-8"))
        return encoded_bytes.decode("utf-8")
    elif mode == "decode":
        try:
            decoded_bytes = base64.b64decode(text.encode("utf-8"))
            return decoded_bytes.decode("utf-8")
        except Exception:
            return "Invalid Base64 input!"


def simple_substitution_cipher(mode, message, key):
    # key: a 26-letter string representing substitution for letters A-Z
    if len(key) != 26 or not key.isalpha():
        return "Key must be 26 alphabetic characters."

    key = key.upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = []

    if mode == "encrypt":
        mapping = {alphabet[i]: key[i] for i in range(26)}
    else:
        mapping = {key[i]: alphabet[i] for i in range(26)}

    for char in message:
        if char.isalpha():
            is_upper = char.isupper()
            char_upper = char.upper()
            substituted = mapping.get(char_upper, char_upper)
            result.append(substituted if is_upper else substituted.lower())
        else:
            result.append(char)
    return "".join(result)


def bcrypt_hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def bcrypt_check_password(password, hashed):
    try:
        valid = bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        return (
            "Password matches hash ✅" if valid else "Password does not match hash ❌"
        )
    except Exception:
        return "Invalid hash or password."


def main():
    parser = argparse.ArgumentParser(
        description="🔐 SecureCLI - Encryption, hashing, password utils"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Caesar Cipher
    caesar_parser = subparsers.add_parser(
        "caesar", help="Caesar cipher encryption/decryption"
    )
    caesar_parser.add_argument("mode", choices=["encrypt", "decrypt"])
    caesar_parser.add_argument("message", help="Message to encrypt or decrypt")
    caesar_parser.add_argument("shift", type=int, help="Shift value")

    # Base64
    base64_parser = subparsers.add_parser("base64", help="Base64 encode/decode")
    base64_parser.add_argument("mode", choices=["encode", "decode"])
    base64_parser.add_argument("text", help="Text to encode or decode")

    # SHA-256
    sha_parser = subparsers.add_parser("sha256", help="Generate SHA-256 hash")
    sha_parser.add_argument("text", help="Text to hash")

    # File hash (SHA-256)
    filehash_parser = subparsers.add_parser(
        "filehash", help="Generate SHA-256 hash of a file"
    )
    filehash_parser.add_argument("filepath", help="Path to the file")

    # Password Strength Checker
    pw_check_parser = subparsers.add_parser("checkpw", help="Check password strength")
    pw_check_parser.add_argument("password", help="Password to check")

    # Password Generator
    genpw_parser = subparsers.add_parser(
        "genpw", help="Generate random strong password"
    )
    genpw_parser.add_argument(
        "-l", "--length", type=int, default=12, help="Password length (default 12)"
    )
    genpw_parser.add_argument(
        "-s", "--special", action="store_true", help="Include special characters"
    )

    # XOR cipher
    xor_parser = subparsers.add_parser("xor", help="XOR cipher encrypt/decrypt")
    xor_parser.add_argument("message", help="Message to encrypt/decrypt")
    xor_parser.add_argument("key", help="Key for XOR cipher")

    # Simple Substitution cipher
    subs_parser = subparsers.add_parser(
        "substitution", help="Simple substitution cipher encrypt/decrypt"
    )
    subs_parser.add_argument("mode", choices=["encrypt", "decrypt"])
    subs_parser.add_argument("message", help="Message to encrypt or decrypt")
    subs_parser.add_argument("key", help="26-letter substitution key")

    # bcrypt hash password
    bcrypt_hash_parser = subparsers.add_parser(
        "bcrypt_hash", help="Hash password with bcrypt"
    )
    bcrypt_hash_parser.add_argument("password", help="Password to hash")

    # bcrypt verify password
    bcrypt_check_parser = subparsers.add_parser(
        "bcrypt_check", help="Verify password against bcrypt hash"
    )
    bcrypt_check_parser.add_argument("password", help="Password to verify")
    bcrypt_check_parser.add_argument("hash", help="bcrypt hash")

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = main()

    if args.command == "caesar":
        print(caesar_cipher(args.mode, args.message, args.shift))

    elif args.command == "base64":
        print(base64_convert(args.mode, args.text))

    elif args.command == "sha256":
        print(generate_sha256(args.text))

    elif args.command == "filehash":
        print(hash_file_sha256(args.filepath))

    elif args.command == "checkpw":
        print(check_password_strength(args.password))

    elif args.command == "genpw":
        print(generate_password(args.length, args.special))

    elif args.command == "xor":
        print(xor_cipher(args.message, args.key))

    elif args.command == "substitution":
        print(simple_substitution_cipher(args.mode, args.message, args.key))

    elif args.command == "bcrypt_hash":
        print(bcrypt_hash_password(args.password))

    elif args.command == "bcrypt_check":
        print(bcrypt_check_password(args.password, args.hash))

    else:
        print("Command not implemented yet.")
