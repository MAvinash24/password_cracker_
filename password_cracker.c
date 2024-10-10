#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

// Function to compute hash of a plaintext using a specified algorithm
void compute_hash(const unsigned char *input, size_t length, const EVP_MD *md, unsigned char *output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "Error initializing digest\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_DigestUpdate(mdctx, input, length)) {
        fprintf(stderr, "Error updating digest\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    unsigned int md_len;
    if (1 != EVP_DigestFinal_ex(mdctx, output, &md_len)) {
        fprintf(stderr, "Error finalizing digest\n");
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
}

// Function to verify user-provided hash against hashes of passwords using a specified algorithm
void verify_hash(const char *user_hash, const char *algorithm_name) {
    const EVP_MD *md = EVP_get_digestbyname(algorithm_name);
    if (!md) {
        fprintf(stderr, "Unknown algorithm: %s\n", algorithm_name);
        return;
    }

    printf("Verifying hash using algorithm: %s\n", algorithm_name);

    unsigned char user_hash_binary[EVP_MAX_MD_SIZE];
    size_t user_hash_length = strlen(user_hash) / 2;
    for (size_t i = 0; i < user_hash_length; ++i) {
        sscanf(user_hash + 2 * i, "%2hhx", &user_hash_binary[i]);
    }

    printf("User-provided hash (binary): ");
    for (size_t i = 0; i < user_hash_length; ++i) {
        printf("%02x", user_hash_binary[i]);
    }
    printf("\n");

    clock_t start_time = clock(); // Start timing

    // Open the rockyou password list
    FILE *file = fopen("rockyou.txt", "r");
    if (!file) {
        perror("Error opening rockyou.txt");
        return;
    }

    char password[256];
    while (fgets(password, sizeof(password), file) != NULL) {
        // Remove newline character
        password[strcspn(password, "\n")] = '\0';

        size_t password_length = strlen(password);
        unsigned char computed_hash[EVP_MAX_MD_SIZE];
        unsigned int computed_hash_length = EVP_MD_size(md);
        compute_hash((const unsigned char *)password, password_length, md, computed_hash);

        printf("Computed hash for '%s': ", password);
        for (size_t j = 0; j < computed_hash_length; ++j) {
            printf("%02x", computed_hash[j]);
        }
        printf("\n");

        int match = 1;
        for (size_t j = 0; j < computed_hash_length; ++j) {
            if (computed_hash[j] != user_hash_binary[j]) {
                match = 0;
                break;
            }
        }

        if (match) {
            clock_t end_time = clock(); // Stop timing
            double elapsed_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
            printf("**********Password found for %s: %s\n", algorithm_name, password);
            printf("**********Time taken to find the password: %f seconds\n", elapsed_time);
            fclose(file);
            return;
        }
    }

    fclose(file);
    printf("Password not found for the given hash using %s.\n", algorithm_name);
}

int main() {
    char user_hash_str[256]; // Allocate memory to store user-provided hash
    printf("Enter the hash (in hexadecimal format): ");
    if (fgets(user_hash_str, sizeof(user_hash_str), stdin) == NULL) {
        fprintf(stderr, "Error reading input\n");
        return EXIT_FAILURE;
    }

    // Remove newline character from user-provided hash string
    user_hash_str[strcspn(user_hash_str, "\n")] = '\0';

    // List of supported hashing algorithms
    const char *algorithms[] = {
        "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"
    };

    // Verify the user-provided hash using each algorithm
    for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); ++i) {
        verify_hash(user_hash_str, algorithms[i]);
    }

    return 0;
}
