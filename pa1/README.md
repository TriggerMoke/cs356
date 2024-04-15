PA1

How to Run:
    ./cipher <(B)lock or (S)tream cipher> <input file> <output file> <key file> <(E)ncryption or (D)ecryption>

    Example:
    ./cipher B input.txt sample_encrypted.txt key.txt E
    ./cipher B sample_encrypted.txt sample_decrypted.txt key.txt D

Make commands:
    make - compiles the program
    make package - creates a .tar.gz file
    make clean - removes all files created by make
    make block - runs the program with sample.txt in block cipher mode
    make stream - runs the program with sample.txt in stream cipher mode
    Both of the block and stream commands provide an encrypted and decrypted file