#include "../ecop/EC.h"
#include <stdio.h>
#include <stdbool.h>
#include <gmp.h>
#include <openssl/rand.h>

void configure_public_params(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point *G);
void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point G, char *filename);
void ecdsa_signature(mpz_t r, mpz_t s, mpz_t d, mpz_t m, mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point G);
bool ecdsa_verification(mpz_t r, mpz_t s, mpz_t m, char *filename);

int main(void) {
    mpz_t p, a, b, q, d, m, r, s;
    ec_point G;

    mpz_inits(p, a, b, q, d, m, r, s, G.x, G.y, NULL);

    configure_public_params(p, a, b, q, &G);

    char filename[] = "ecdsa_keypair.txt";
    generate_key_pair(p, a, b, q, G, filename);

    printf("Enter the private key d: ");
    mpz_inp_str(d, stdin, 10);

    printf("Enter a message m: ");
    mpz_inp_str(m, stdin, 10);

    if (mpz_cmp_ui(m, 0) <= 0 || mpz_cmp(m, q) >= 0) {
        fprintf(stderr, "Error: m must be in the range 0 < m < q\n");
        mpz_clears(p, a, b, q, d, m, r, s, G.x, G.y, NULL);
        return 1;
    }

    ecdsa_signature(r, s, d, m, p, a, b, q, G);

    gmp_printf("Signature: (r, s) = (%Zd, %Zd)\n", r, s);

    bool is_valid = ecdsa_verification(r, s, m, filename);
    if (is_valid) {
        printf("The signature is valid.\n");
    } else {
        printf("The signature is not valid.\n");
    }

    mpz_clears(p, a, b, q, d, m, r, s, G.x, G.y, NULL);

    return 0;
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

void generate_key_pair(mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point G, char *filename) {
    mpz_t d;
    ec_point B;

    mpz_inits(d, B.x, B.y, NULL);

    unsigned char buffer[32];
    if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
        perror("Error generating secure random bytes\n");
        mpz_clears(d, B.x, B.y, NULL);
        return;
    }

    mpz_import(d, sizeof(buffer), 1, sizeof(buffer[0]), 0, 0, buffer);
    mpz_mod(d, d, q);

    B = point_multiplication(a, b, p, G, d);

    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file\n");
        mpz_clears(d, B.x, B.y, NULL);
        return;
    }

    if (gmp_fprintf(file, "p = %Zd, ", p) < 0 ||
        gmp_fprintf(file, "a = %Zd, ", a) < 0 ||
        gmp_fprintf(file, "b = %Zd, ", b) < 0 ||
        gmp_fprintf(file, "q = %Zd, ", q) < 0 ||
        gmp_fprintf(file, "G = (%Zd:%Zd:%d), ", G.x, G.y, G.z) < 0 ||
        gmp_fprintf(file, "B = (%Zd:%Zd:%d)\n", B.x, B.y, B.z) < 0) {
        perror("Error writing to file\n");
    }

    fclose(file);

    gmp_printf("Private key d: %Zd\n", d);
    gmp_printf("Public key B: (%Zd:%Zd:%d)\n", B.x, B.y, B.z);

    mpz_clears(d, B.x, B.y, NULL);
}

void ecdsa_signature(mpz_t r, mpz_t s, mpz_t d, mpz_t m, mpz_t p, mpz_t a, mpz_t b, mpz_t q, ec_point G) {
    mpz_t k, k_inv, temp;
    ec_point R;

    mpz_inits(k, k_inv, R.x, R.y, temp, NULL);

    do {
        unsigned char buffer[32];
        if (RAND_bytes(buffer, sizeof(buffer)) != 1) {
            perror("Error generating secure random bytes\n");
            mpz_clears(k, k_inv, R.x, R.y, temp, NULL);
            return;
        }

        mpz_import(k, sizeof(buffer), 1, sizeof(buffer[0]), 0, 0, buffer);
        mpz_mod(k, k, q);
    } while (mpz_cmp_ui(k, 1) < 0)

    R = point_multiplication(a, b, p, G, k);

    mpz_set(r, R.x);

    if (mpz_invert(k_inv, k, q) == 0) {
        perror("K has no modular inverse\n");
        mpz_clears(k, k_inv, R.x, R.y, temp, NULL);
        return;
    }

    mpz_mul(temp, d, r);
    mpz_add(temp, temp, m);
    mpz_mod(temp, temp, q);

    mpz_mul(s, temp, k_inv);
    mpz_mod(s, s, q);

    mpz_clears(k, k_inv, R.x, R.y, temp, NULL);
}

bool ecdsa_verification(mpz_t r, mpz_t s, mpz_t m, char *filename) {
    mpz_t w, aux_1, aux_2, p, a, b, q;
    ec_point G, B, P, P_temp_1, P_temp_2;

    mpz_inits(w, aux_1, aux_2, p, a, b, q, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);

    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file\n");
        mpz_clears(w, aux_1, aux_2, p, a, b, q, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    if (gmp_fscanf(file, "p = %Zd, a = %Zd, b = %Zd, q = %Zd, G = (%Zd:%Zd:%d), B = (%Zd:%Zd:%d)\n", p, a, b, q, G.x, G.y, G.z, B.x, B.y, B.z) != 10) {
        perror("Error reading from public key file\n");
        fclose(file);
        mpz_clears(w, aux_1, aux_2, p, a, b, q, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    fclose(file);

    if (mpz_invert(w, s, q) == 0) {
        perror("S has no modular inverse\n");
        mpz_clears(w, aux_1, aux_2, p, a, b, q, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
        return false;
    }

    mpz_mul(aux_1, w, m);
    mpz_mod(aux_1, aux_1, q);

    mpz_mul(aux_2, w, r);
    mpz_mod(aux_2, aux_2, q);
   

    P_temp_1 = point_multiplication(a, b, p, G, aux_1)
    P_temp_2 = point_multiplication(a, b, p, B, aux_2)
    P = point_addition(a, b, p, P_temp_1, P_temp_2);

    bool is_valid = (mpz_cmp(P.x, r) == 0);

    mpz_clears(w, aux_1, aux_2, p, a, b, q, G.x, G.y, B.x, B.y, P.x, P.y, P_temp_1.x, P_temp_1.y, P_temp_2.x, P_temp_2.y, NULL);
    
    return is_valid;
}
