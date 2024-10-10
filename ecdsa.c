#include "../ecop/EC.h"
#include <stdio.h>
#include <openssl/rand.h>

void configure_public_params(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G);
void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *filename);
void ecdsa_signature(mpz_t d, mpz_t m, mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *filename);
bool ecdsa_verification(mpz_t m, char *pubkey_file, char *signature_file);

int main(void) {
    mpz_t p, a, b, q, d, m;
    ec_point G;
    int option;
    bool keys_generated = false, signature_generated = false;

    mpz_inits(p, a, b, q, d, m, G.x, G.y, NULL);

    while (1) {
        printf("\nMenu:\n");
        printf("1. Generate Keys\n");
        printf("2. Sign Message\n");
        printf("3. Verify Signature\n");
        printf("4. Exit\n");
        printf("Select an option: ");
        scanf("%d", &option);

        switch (option) {
            case 1:
                configure_public_params(p, a, b, q, &G);
                generate_key_pair(p, a, b, q, &G, "ecdsa_keypair.txt");
                keys_generated = true;
                break;
            case 2:
                if (!keys_generated) {
                    printf("Please generate keys first.\n");
                    break;
                }
                printf("Enter the private key d: ");
                mpz_inp_str(d, stdin, 10);

                printf("Enter a message m: ");
                mpz_inp_str(m, stdin, 10);

                if (mpz_cmp_ui(m, 0) <= 0 || mpz_cmp(m, q) >= 0) {
                    fprintf(stderr, "Error: m must be in the range 0 < m < q\n");
                    break;
                }

                ecdsa_signature(d, m, p, a, b, q, &G, "ecdsa_rs.txt");
                signature_generated = true;
                break;
            case 3:
                if (!signature_generated) {
                    printf("Please sign a message first.\n");
                    break;
                }

                printf("Enter the message m to verify: ");
                mpz_inp_str(m, stdin, 10);

                if (mpz_cmp_ui(m, 0) <= 0 || mpz_cmp(m, q) >= 0) {
                    fprintf(stderr, "Error: m must be in the range 0 < m < q\n");
                    break;
                }

                ecdsa_verification(m, "ecdsa_keypair.txt", "ecdsa_rs.txt") ?
                    printf("The signature is valid.\n") :
                    printf("The signature is not valid.\n");

                break;
            case 4:
                printf("Exiting program.\n");
                mpz_clears(p, a, b, q, d, m, G.x, G.y, NULL);
                return 0;
            default:
                printf("Invalid option. Please select again.\n");
                break;
        }
    }
}

void configure_public_params(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G) {
    printf("Enter a prime number p: ");
    mpz_inp_str(p, stdin, 10);

    printf("Enter coefficient a for the elliptic curve: ");
    mpz_inp_str(a, stdin, 10);

    printf("Enter coefficient b for the elliptic curve: ");
    mpz_inp_str(b, stdin, 10);

    printf("Enter the order q of the generator point G: ");
    mpz_inp_str(q, stdin, 10);

    printf("Enter the generator point G coordinates (xG:yG:1):\n");
    printf("xG = ");
    mpz_inp_str(G->x, stdin, 10);
    printf("yG = ");
    mpz_inp_str(G->y, stdin, 10);
    G->z = 1;
}

void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *filename) {
    mpz_t d;
    ec_point B;

    mpz_inits(d, B.x, B.y, NULL);

    unsigned char buffer[32];
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        perror("Error generating secure random bytes");
        mpz_clears(d, B.x, B.y, NULL);
        return;
    }

    mpz_import(d, sizeof(buffer), 1, sizeof(buffer[0]), 0, 0, buffer);
    mpz_mod(d, d, q);

    B = point_multiplication(a, b, p, G, d);

    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        mpz_clears(d, B.x, B.y, NULL);
        return;
    }

    if (gmp_fprintf(file, "Public key: (") < 0 ||
            gmp_fprintf(file, "%Zd, ", p) < 0 ||
            gmp_fprintf(file, "%Zd, ", a) < 0 ||
            gmp_fprintf(file, "%Zd, ", b) < 0 ||
            gmp_fprintf(file, "%Zd, ", q) < 0 ||
            gmp_fprintf(file, "(%Zd:%Zd:%d), ", G->x, G->y, G->z) < 0 ||
            gmp_fprintf(file, "(%Zd:%Zd:%d))\n", B.x, B.y, B.z) < 0) {
        perror("Error writing to file");
    }

    fclose(file);

    gmp_printf("Private key d: %Zd\n", d);
    gmp_printf("Public key B: (%Zd:%Zd:%d)\n", B.x, B.y, B.z);

    mpz_clears(d, B.x, B.y, NULL);
}

void ecdsa_signature(mpz_t d, mpz_t m, mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G, char *filename) {
    mpz_t r, s, k, k_inv, temp;
    ec_point R;

    mpz_inits(r, s, k, k_inv, R.x, R.y, temp, NULL);

    do {
        unsigned char buffer[32];
        if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
            perror("Error generating secure random bytes");
            mpz_clears(r, s, k, k_inv, R.x, R.y, temp, NULL);
            return;
        }

        mpz_import(k, sizeof(buffer), 1, sizeof(buffer[0]), 0, 0, buffer);
        mpz_mod(k, k, q);
    } while (mpz_cmp_ui(k, 1) < 0);

    R = point_multiplication(a, b, p, G, k);

    mpz_set(r, R.x);

    if (mpz_invert(k_inv, k, q) == 0) {
        perror("K has no modular inverse");
        mpz_clears(r, s, k, k_inv, R.x, R.y, temp, NULL);
        return;
    }

    mpz_mul(temp, d, r);
    mpz_add(temp, temp, m);
    mpz_mod(temp, temp, q);

    mpz_mul(s, temp, k_inv);
    mpz_mod(s, s, q);

    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        mpz_clears(r, s, k, k_inv, R.x, R.y, temp, NULL);
        return;
    }

    if (gmp_fprintf(file, "(%Zd, ", r) < 0 ||
            gmp_fprintf(file, "%Zd)\n", s) < 0) {
        perror("Error writing to file");
    }

    fclose(file);

    gmp_printf("Signature: (r, s) = (%Zd, %Zd)\n", r, s);

    mpz_clears(r, s, k, k_inv, R.x, R.y, temp, NULL);
}

bool ecdsa_verification(mpz_t m, char *pubkey_file, char *signature_file) {
    mpz_t w, aux_1, aux_2, p, a, b, q, r, s;
    ec_point G, B, P, P_temp_1, P_temp_2;

    mpz_inits(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);

    FILE *file = fopen(pubkey_file, "r");
    if (file == NULL) {
        perror("Error opening public key file");
        mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    if (gmp_fscanf(file, "Public key: (%Zd, %Zd, %Zd, %Zd, (%Zd:%Zd:1), (%Zd:%Zd:1))\n", p, a, b, q, G.x, G.y, B.x, B.y) != 8) {
        perror("Error reading from public key file");
        fclose(file);
        mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    fclose(file);

    G.z = 1;
    B.z = 1;

    file = fopen(signature_file, "r");
    if (file == NULL) {
        perror("Error opening signature file");
        mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    if (gmp_fscanf(file, "(%Zd, %Zd)\n", r, s) != 2) {
        perror("Error reading from signature file");
        fclose(file);
        mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    fclose(file);

    if (mpz_invert(w, s, q) == 0) {
        perror("S has no modular inverse");
        mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    mpz_mul(aux_1, w, m);
    mpz_mod(aux_1, aux_1, q);

    mpz_mul(aux_2, w, r);
    mpz_mod(aux_2, aux_2, q);


    P_temp_1 = point_multiplication(a, b, p, &G, aux_1);
    P_temp_2 = point_multiplication(a, b, p, &B, aux_2);
    P = point_addition(a, b, p, &P_temp_1, &P_temp_2);

    bool is_valid = (mpz_cmp(P.x, r) == 0);

    mpz_clears(w, aux_1, aux_2, p, a, b, q, r, s, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);

    return is_valid;
}
