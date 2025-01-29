# ECDSA Implementation in C

This project is a simple implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA) in C. ECDSA is a cryptographic algorithm used for digital signatures, providing a secure way to verify the authenticity of digital messages or documents.

## Table of Contents
- [Requirements](#requirements)
- [Compilation](#compilation)
- [Usage](#usage)
- [Example](#example)

## Requirements

To compile and run this project, you need the following:

- **GCC** (GNU Compiler Collection) or any other C compiler.
- **GMP** (GNU Multiple Precision Arithmetic Library) for handling large integers.
- **OpenSSL** for generating secure random numbers.

### Installing Dependencies

On a Debian-based system (e.g., Ubuntu), you can install the required dependencies using the following commands:

```bash
sudo apt-get update
sudo apt-get install build-essential libgmp-dev libssl-dev
```

## Compilation

To compile the code, navigate to the directory containing the source files and run the following command:

```bash
gcc -o ecdsa ecdsa.c -lgmp -lcrypto
```

This will generate an executable named `ecdsa`.

## Usage

The program provides a simple menu-driven interface to generate key pairs, sign messages, and verify signatures using ECDSA.

### Running the Program

To run the program, execute the generated binary:

```bash
./ecdsa
```

You will be presented with a menu offering the following options:

1. **Generate Keys**: Generates a public-private key pair and saves it to a file.
2. **Sign Message**: Signs a message using the private key and saves the signature to a file.
3. **Verify Signature**: Verifies the signature of a message using the public key.
4. **Exit**: Exits the program.

## Example

### Step 1: Generate Keys

1. Select option `1` to generate keys.
2. Enter the required parameters:
   - A prime number `p`.
   - Coefficients `a` and `b` for the elliptic curve.
   - The order `q` of the generator point `G`.
   - The coordinates of the generator point `G` (xG, yG).

The program will generate a private key `d` and a public key `B`, and save them to `ecdsa_keypair.txt`.

### Step 2: Sign a Message

1. Select option `2` to sign a message.
2. Enter the private key `d` and the message `m` to sign.
3. The program will generate a signature `(r, s)` and save it to `ecdsa_rs.txt`.

### Step 3: Verify the Signature

1. Select option `3` to verify the signature.
2. Enter the message `m` to verify.
3. The program will check the signature against the public key and output whether the signature is valid.

### Example Output

```bash
Menu:
1. Generate Keys
2. Sign Message
3. Verify Signature
4. Exit
Select an option: 1
Enter a prime number p: 23
Enter coefficient a for the elliptic curve: 1
Enter coefficient b for the elliptic curve: 1
Enter the order q of the generator point G: 7
Enter the generator point G coordinates (xG:yG:1):
xG = 5
yG = 1
Private key d: 3
Public key B: (10:8:1)

Menu:
1. Generate Keys
2. Sign Message
3. Verify Signature
4. Exit
Select an option: 2
Enter the private key d: 3
Enter a message m: 5
Signature: (r, s) = (10, 5)

Menu:
1. Generate Keys
2. Sign Message
3. Verify Signature
4. Exit
Select an option: 3
Enter the message m to verify: 5
The signature is valid.
```

This example demonstrates the basic workflow of generating keys, signing a message, and verifying the signature using ECDSA.
