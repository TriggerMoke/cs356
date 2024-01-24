// Aidan Michalos

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void block_cipher(FILE *in, FILE *out, FILE *key, char mode);
void stream_cipher(FILE *in, FILE *out, FILE *key, char mode);
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
        block_cipher(input_file, output_file, key_file, mode);
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

        // This actually does not work lol
        // key_buffer[key_size - 1] = '\0';  // Add null character at the end of the buffer

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

// Function to perform block cipher encryption/decryption
void block_cipher(FILE *in, FILE *out, FILE *key, char mode)
{

    // Read the key into a buffer
    char key_buffer[16];
    size_t key_size = fread(key_buffer, 1, 16, key);

    // Check key size for block cipher
    if (key_size != 16)
    {
        printf("Error: Key size for block cipher must be 16 bytes.\n");
        exit(1);
    }

    // Read the input file into a buffer
    char buffer[16];
    size_t bytes;
    while ((bytes = fread(buffer, 1, 16, in)) > 0)
    {
        // Pad the buffer with 0x81 if necessary
        if (bytes < 16 && mode == 'E')
        {
            memset(buffer + bytes, 0x81, 16 - bytes);
        }

        if (mode == 'E')
        {
            // XOR the buffer with the key
            for (int i = 0; i < 16; i++)
            {
                buffer[i] ^= key_buffer[i];
            }

            // Swap bytes according to the key
            int start = 0, end = 15;
            for (int i = 0; i < 16; i++)
            {
                if ((key_buffer[i] % 2) == 1)
                {
                    char temp = buffer[start];
                    buffer[start] = buffer[end];
                    buffer[end] = temp;
                    end--;
                }
                start++;
                if (start >= end)
                {
                    break;
                }
            }
        }
        else
        { // mode == 'D'
            // Swap bytes according to the key
            int start = 0, end = 15;
            for (int i = 0; i < 16; i++)
            {
                if ((key_buffer[i] % 2) == 1)
                {
                    char temp = buffer[start];
                    buffer[start] = buffer[end];
                    buffer[end] = temp;
                    end--;
                }
                start++;
                if (start >= end)
                {
                    break;
                }
            }

            // XOR the buffer with the key
            for (int i = 0; i < 16; i++)
            {
                buffer[i] ^= key_buffer[i];
            }

            // Check for padding and adjust bytes if necessary
            for (int i = 15; i >= 0; i--)
            {
                if (buffer[i] == (char)0x81)
                {
                    bytes = i;
                    break;
                }
            }
        }

        // Write the result to the output file
        fwrite(buffer, 1, bytes, out);
    }

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