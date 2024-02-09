#include <iostream>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

// Constants
const int BLOCK_SIZE = 16;
const char PADDING_CHAR = 0x81;

std::ifstream openInputFile(const std::string& filename);
std::ofstream openOutputFile(const std::string& filename);

std::vector<char> readKey(std::ifstream& keyFile);
std::vector<char> padBlock(const std::vector<char>& block);
std::vector<char> unpadBlock(const std::vector<char>& block);
void xorBlock(std::vector<char>& block, const std::vector<char>& key);
void swapBytes(std::vector<char>& block, const std::vector<char>& key);
void blockCipher(std::ifstream& inputFile, std::ofstream& outputFile, std::ifstream& keyFile, char mode);
void streamCipher(std::ifstream& inputFile, std::ofstream& outputFile, std::ifstream& keyFile, char mode);

int main(int argc, char* argv[]) {
    if (argc != 6) {
        std::cerr << "Usage: ./cipher [B|S] inputFileName outputFileName keyFileName [E|D]\n"
                  << "  [B|S] - B for block cipher, S for stream cipher\n"
                  << "  [E|D] - E for encryption, D for decryption\n"
                  << "  inputFileName - name of the input file\n"
                  << "  outputFileName - name of the output file\n"
                  << "  keyFileName - name of the key file\n"
                  << "Example: ./cipher B input.txt output.txt key.txt E\n";
        return 1;
    }

    char cipherType = argv[1][0];
    char mode = argv[5][0];

    // Modes
    if (cipherType != 'B' && cipherType != 'S') {
        std::cerr << "Invalid cipher type. Must be 'B' for block or 'S' for stream.\n";
        return 1;
    }
    if (mode != 'E' && mode != 'D') {
        std::cerr << "Invalid mode. Must be 'E' for encryption or 'D' for decryption.\n";
        return 1;
    }

    try {
        auto inputFile = openInputFile(argv[2]);
        auto outputFile = openOutputFile(argv[3]);
        auto keyFile = openInputFile(argv[4]);

        if (cipherType == 'B') {
            blockCipher(inputFile, outputFile, keyFile, mode);
        } else { // cipherType == 'S'
            streamCipher(inputFile, outputFile, keyFile, mode);
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}

// File I/O helper functions
std::ifstream openInputFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open input file: " + filename);
    }
    return file;
}

std::ofstream openOutputFile(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open or create output file: " + filename);
    }
    return file;
}

// Block Cipher main function
void blockCipher(std::ifstream& inputFile, std::ofstream& outputFile, std::ifstream& keyFile, char mode) {
    auto key = readKey(keyFile);
    std::vector<char> block(BLOCK_SIZE);

    while (inputFile.read(block.data(), BLOCK_SIZE) || inputFile.gcount() > 0) {
        block.resize(inputFile.gcount());

        if (mode == 'E') {
            // Encryption: Pad (if required) -> Encrypt (XOR) -> Swap
            if (block.size() < BLOCK_SIZE) {
                block = padBlock(block);
            }
            xorBlock(block, key);
            swapBytes(block, key);
        } else { // mode == 'D'
            // Decryption: Swap -> Decrypt (XOR) -> Unpad (if required)
            swapBytes(block, key);
            xorBlock(block, key);
            block = unpadBlock(block);
        }

        outputFile.write(block.data(), block.size());
        block.resize(BLOCK_SIZE); // Reset block size for next read
    }
}


// Block cipher helper functions
// Read the key from the key file
std::vector<char> readKey(std::ifstream& keyFile) {
    std::vector<char> key(BLOCK_SIZE);
    if (!keyFile.read(key.data(), BLOCK_SIZE)) {
        throw std::runtime_error("Failed to read the key or key is not the expected length.");
    }
    return key;
}

// Pad the block with the padding character if it is less than the block size
std::vector<char> padBlock(const std::vector<char>& block) {
    std::vector<char> paddedBlock = block;
    size_t paddingNeeded = BLOCK_SIZE - block.size();
    paddedBlock.insert(paddedBlock.end(), paddingNeeded, PADDING_CHAR);
    return paddedBlock;
}

// Remove the padding character from the end of the block
std::vector<char> unpadBlock(const std::vector<char>& block) {
    size_t i = block.size();
    while (i > 0 && block[i - 1] == PADDING_CHAR) --i;
    return std::vector<char>(block.begin(), block.begin() + i);
}

// XOR the block with the key
void xorBlock(std::vector<char>& block, const std::vector<char>& key) {
    for (size_t i = 0; i < block.size(); ++i) {
        block[i] ^= key[i % key.size()];
    }
}

// Swap the bytes in the block based on the key
void swapBytes(std::vector<char>& block, const std::vector<char>& key) {
    int start = 0, end = block.size() - 1;
    while (start < end) {
        for (int i = 0; i < key.size() && start < end; ++i) {
            if ((key[i] % 2) == 1) {
                std::swap(block[start], block[end]);
                --end;
            }
            ++start;
        }
    }
}

// Stream Cipher (mode isn't used here but is included for consistency)
void streamCipher(std::ifstream& inputFile, std::ofstream& outputFile, std::ifstream& keyFile, char mode) {
    // Read the key into a string
    std::string key((std::istreambuf_iterator<char>(keyFile)), std::istreambuf_iterator<char>());

    // Ensure the key is read successfully
    if (key.empty()) {
        throw std::runtime_error("Key file is empty or could not be read.");
    }

    // Process the input file in chunks to handle potentially large files
    const size_t bufferSize = 1024;
    std::vector<char> buffer(bufferSize);
    size_t bytesRead;

    while (!inputFile.eof()) {
        inputFile.read(buffer.data(), bufferSize);
        bytesRead = inputFile.gcount();

        // XOR each byte of the buffer with the key, looping over the key as needed
        for (size_t i = 0; i < bytesRead; ++i) {
            buffer[i] ^= key[i % key.size()];
        }

        // Write the processed chunk to the output file
        outputFile.write(buffer.data(), bytesRead);
    }
}
