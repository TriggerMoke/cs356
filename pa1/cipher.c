// Aidan Michalos
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCK_SIZE 16
#define KEY_SIZE 16
#define padChar 0x81

// Block Cipher functions
void xor(FILE *in, FILE *out, FILE *key);
void byteswap(FILE *in, FILE *out);
void pad(FILE *in, FILE *out);
void removePad(FILE *in, FILE *out);
void blockEncrypt(FILE *in, FILE *out, FILE *key);
void blockDecrypt(FILE *in, FILE *out, FILE *key);

// Stream Cipher function
void stream_cipher(FILE *in, FILE *out, FILE *key, char mode);

// Function to open files
FILE *open_file(char *filename, char *file_option, int argv_index);

int main(int argc, char *argv[])
{

    if (argc != 6)
    {
        printf("Error: Incorrect number of arguments.\n");
        return 1;
    }

    char cipher_type = argv[1][0];
    char mode = argv[5][0];

    printf("Debug: Cipher type = %c, Mode = %c\n", cipher_type, mode);

    if (cipher_type != 'B' && cipher_type != 'S')
    {
        printf("Error: Invalid cipher type. Must be 'B' or 'S'.\n");
        return 1;
    }

    if (mode != 'E' && mode != 'D')
    {
        printf("Error: Invalid mode. Must be 'E' or 'D'.\n");
        return 1;
    }

    FILE *input_file = open_file(argv[2], "rb", 2);
    FILE *output_file = open_file(argv[3], "wb", 3);
    FILE *key_file = open_file(argv[4], "rb", 4);

    clock_t start_time, end_time;
    double cpu_time_used;

    // clock to measure time for encryption/decryption
    start_time = clock();

    if (cipher_type == 'B')
    {
        if(mode == 'E')
        {
            blockEncrypt(input_file, output_file, key_file);
        }
        else // mode == 'D'
        {
            blockDecrypt(input_file, output_file, key_file);
        }
    }
    else
    {
        stream_cipher(input_file, output_file, key_file, mode);
    }

    // time calculation
    end_time = clock();
    cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("Time taken for encryption/decryption: %f seconds\n", cpu_time_used);

    fclose(input_file);
    fclose(output_file);
    fclose(key_file);

    return 0;
}

// Function to open file and avoid code duplication
FILE *open_file(char *filename, char *file_option, int argv_index)
{
    FILE *file = fopen(filename, file_option);
    if (file == NULL)
    {
        printf("Error: File %s does not exist.\n", filename);
        exit(1);
    }

    // If this is the key file, clean it
    if (argv_index == 4)
    {
        char key_buffer[16];
        size_t key_size = 0;
        int c;
        while ((c = fgetc(file)) != EOF)
        {
            if (c != '\n')
            {
                key_buffer[key_size++] = c;
            }
        }
        fclose(file);

        // Reopen the key file in write mode and write the cleaned key
        file = fopen(filename, "wb");
        if (file == NULL)
        {
            printf("Error: Could not open key file in write mode.\n");
            exit(1);
        }

        fwrite(key_buffer, 1, key_size, file);
        fclose(file);

        // Reopen the key file in read mode
        file = fopen(filename, "rb");
        if (file == NULL)
        {
            printf("Error: Could not reopen key file in read mode.\n");
            exit(1);
        }
    }

    return file;
}

//Functions to perform block cipher encryption/decryption

// Function to XOR Blocks
void xor(FILE *in, FILE *out, FILE *key){
    char buffer[BLOCK_SIZE];
    char key_buffer[KEY_SIZE];
    size_t bytes;
    size_t key_size = fread(key_buffer, 1, 16, key);
    while ((bytes = fread(buffer, 1, 16, in)) > 0)
    {
        for (int i = 0; i < 16; i++)
        {
            buffer[i] ^= key_buffer[i];
        }
        fwrite(buffer, 1, 16, out);
    }
}
// Function to swap bytes
void byteswap(FILE *in, FILE *out){
    char buffer[BLOCK_SIZE];
    //char key_buffer[KEY_SIZE];
    size_t bytes;
    //size_t key_size = fread(key_buffer, 1, 16, key);
    while ((bytes = fread(buffer, 1, 16, in)) > 0)
    {
        for (int i = 0; i < 16; i += 2)
        {
            char temp = buffer[i];
            buffer[i] = buffer[i + 1];
            buffer[i + 1] = temp;
        }
        fwrite(buffer, 1, 16, out);
    }
}
// Function to pad the last block if necessary
void pad(FILE *in, FILE *out){
    char buffer[BLOCK_SIZE];
    size_t bytes;
    while ((bytes = fread(buffer, 1, 16, in)) > 0)
    {
        if (bytes < 16)
        {
            for (int i = bytes; i < 16; i++)
            {
                buffer[i] = padChar;
            }
        }
        fwrite(buffer, 1, 16, out);
    }
}
void removePad(FILE *in, FILE *out){
    char buffer[BLOCK_SIZE];
    char pad = padChar;
    size_t bytes;
    while ((bytes = fread(buffer, 1, 16, in)) > 0)
    {
        if (buffer[15] == pad)
        {
            int i = 15;
            while (buffer[i] == pad)
            {
                i--;
            }
            fwrite(buffer, 1, i + 1, out);
        }
        else
        {
            fwrite(buffer, 1, 16, out);
        }
    }
}
// Block Cipher Encrypt
void blockEncrypt(FILE *in, FILE *out, FILE *key){
    xor(in, out, key);
    byteswap(in, out);
    pad(in, out);
}
// Block Cipher Decrypt
void blockDecrypt(FILE *in, FILE *out, FILE *key){
    removePad(in, out);
    byteswap(in, out);
    xor(in, out, key);
}

// Function to perform stream cipher encryption/decryption & the char mode is unused but still included for consistency
void stream_cipher(FILE *in, FILE *out, FILE *key, char mode)
{
    // Read the key into a buffer
    char key_buffer[16];
    size_t key_size = fread(key_buffer, 1, 16, key);

    // Check key size for stream cipher
    if (key_size == 0)
    {
        printf("Error: Key size for stream cipher must be greater than 0.\n");
        exit(1);
    }

    // Read the input file into a buffer
    char buffer[1];
    size_t bytes;
    size_t key_index = 0;
    while ((bytes = fread(buffer, 1, 1, in)) > 0)
    {
        // XOR the buffer with the key
        buffer[0] ^= key_buffer[key_index];

        // Write the result to the output file
        fwrite(buffer, 1, 1, out);

        // Update the key index
        key_index = (key_index + 1) % key_size;
    }
}