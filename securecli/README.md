# 🔐 SecureCLI - A Simple & Powerful Python CLI Tool

**SecureCLI** is an all-in-one command-line tool for:

- Caesar Cipher Encryption/Decryption
- Base64 Encode/Decode
- SHA-256 Hashing
- Password Strength Checker
- Password Generator
- File Integrity Verifier
- XOR Encryption
- Substitution Cipher
- Secure Hashing (hashlib & bcrypt)

---

## 🚀 Quick Install (One Command)

Run this in your terminal:

```bash
curl -s https://raw.githubusercontent.com/YANTRA-EKA/securecli/main/install.sh | bash
```

# Usage guide

## to conform run this cmd

```bash
securecli -h
```

# Caesar Cipher

```bash
securecli caesar encrypt "HelloWorld" 3
securecli caesar decrypt "KhoorZruog" 3
```

# Base64 Encode/Decode

```bash
securecli base64 encode "OpenAI"
securecli base64 decode "T3BlbkFJ"
```

# SHA-256 Hash

```bash
securecli sha256 "HelloWorld"
```

# Password Strength Checker

```bash
securecli checkpw "MySecureP@ss"
```

# Password Generator

```bash
securecli genpw --length 16 --special
```

# File Integrity Check

```bash
securecli filehash myfile.txt
# Save the output, then later check:
securecli verify myfile.txt <original_hash>
```

# XOR Encryption

```bash
securecli xor encrypt "SecretText" "key123"
securecli xor decrypt "<output_from_encrypt>" "key123"
```

# Substitution Cipher

```
securecli sub encrypt "hello"
securecli sub decrypt "<output>"
```

> [!IMPORTANT]
>
> # Update
>
> ```bash
> cd ~/.securecli && git pull
> ```

# Uninstall

```bash
rm -rf ~/.securecli
sed -i '/securecli/d' ~/.bashrc  # or ~/.zshrc
```
