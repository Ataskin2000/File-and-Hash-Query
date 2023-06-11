#include <iostream>
#include <fstream>  // For working with files
#include <iomanip>  // For output formatting
#include <openssl/evp.h>  // For cryptographic hash functions
#include <sqlite3.h>
#include <stdio.h>
#include <string>
#include <sstream>

static int createDB(const char* s);
static int createTable(const char* s);
static int insertData(const char* s);
static int selectData(const char* s);
static int callback(void* NotUsed, int argc, char** argv, char** azColName);

std::string md5;
std::string sha1;
std::string sha256;

std::string hash_bilgisi;

std::string alper(const char* a) {

    const char* dir = "C:\\Db\\virus2.db";
    sqlite3* DB = nullptr;

    //createDB(dir);
    //createTable(dir);
    //selectData(dir);

    const char* filename = a;

    //const char* filename = "C:\\Test\\output.txt";  // The file to hash
    //const char* hashes[] = { "MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "BLAKE2B", "BLAKE2S", "SHA3_SHA224", "SHA3_SHA256", "SHA3_SHA384", "SHA3_SHA512", "SHAKE128", "SHAKE256"};  // Names of the hash functions to use
    //const EVP_MD* md[] = { EVP_md5(), EVP_sha1(), EVP_sha224(), EVP_sha256(), EVP_sha384(), EVP_sha512(), EVP_blake2b512(), EVP_blake2s256(), EVP_sha3_224(), EVP_sha3_256(), EVP_sha3_384(), EVP_sha3_512(), EVP_shake128(), EVP_shake256()};  // Hash functions to use
    
    const char* hashes[] = { "MD5", "SHA1", "SHA256"};  // Names of the hash functions to use
    const EVP_MD* md[] = { EVP_md5(), EVP_sha1(), EVP_sha256()};  // Hash functions to use


    const int num_hashes = sizeof(md) / sizeof(md[0]);  // Number of hash functions to use

    // Compute message digests for each algorithm for each chunk of data
    const size_t chunk_size = 4096;  // The size of the data chunk to read from the file
    char buffer[chunk_size];  // Buffer to read data from the file

    for (int i = 0; i < num_hashes; i++) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();  // Create a new context for the hash function
        EVP_DigestInit_ex(mdctx, md[i], nullptr);  // Initialize the hash function

        std::ifstream file(filename, std::ios::binary);  // Open the file in binary mode
        while (file.read(buffer, chunk_size)) {  // Read data from the file in chunks
            EVP_DigestUpdate(mdctx, buffer, chunk_size);  // Update the hash function with the data
        }

        size_t remaining_bytes = file.gcount();  // Get the number of bytes left in the file
        if (remaining_bytes > 0) {  // If there are bytes left, read them
            EVP_DigestUpdate(mdctx, buffer, remaining_bytes);  // Update the hash function with the remaining bytes
        }

        unsigned char digest[EVP_MAX_MD_SIZE];  // Buffer to hold the message digest
        unsigned int digest_len = 0;  // Length of the message digest
        EVP_DigestFinal_ex(mdctx, digest, &digest_len);  // Finalize the hash function and get the message digest
        std::cout << hashes[i] << " hash of \"" << filename << "\": ";

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned int k = 0; k < digest_len; k++) {
            ss << std::setw(2) << static_cast<unsigned int>(digest[k]);
        }
        if (i == 0) {
            md5 = ss.str();
            std::cout << md5 << std::endl;
        }
        if (i == 1) {
            sha1 = ss.str();
            std::cout << sha1 << std::endl;
        }
        if (i == 2) {
            sha256 = ss.str();
            std::cout << sha256 << std::endl;
        }
        hash_bilgisi = "MD5: " + md5 + "\n" + "SHA1: " + sha1 + "\n" + "SHA256: " + sha256;

   //     std::cout << std::hex << std::setfill('0');  // Set output formatting to hexadecimal with leading zeros
   //     for (unsigned int j = 0; j < digest_len; j++)
   //         std::cout << std::setw(2) << static_cast<unsigned int>(digest[j]);  // Print each byte of the message digest
   //     std::cout << std::endl;

        

        EVP_MD_CTX_free(mdctx);  // Free the hash function context
        EVP_MD_free(const_cast<EVP_MD*>(md[i]));  // Free the hash function
    }

    //insertData(dir);
    return (hash_bilgisi);
}

static int createDB(const char* s)
{
    sqlite3* DB;
    int exit = 0;

    exit = sqlite3_open(s, &DB);

    sqlite3_close(DB);
    return 0;
}

static int createTable(const char* s)
{
    sqlite3* DB;

    std::string sql = "CREATE TABLE HASH("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "FILENAME TEXT NOT NULL,"
        "MD5 TEXT NOT NULL,"
        "SHA1 TEXT NOT NULL,"
        "SHA256 TEXT NOT NULL)";

    try
    {
        int exit = 0;
        exit = sqlite3_open(s, &DB);

        char* messageError;
        exit = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messageError);

        if (exit != SQLITE_OK)
        {
            std::cerr << "Error Create Table" << std::endl;
            sqlite3_free(messageError);
        }
        else
            std::cout << "Table created successfully" << std::endl;
        sqlite3_close(DB);

    }
    catch (const std::exception & e)
        {
        std::cerr << e.what();
        }
    return 0;
    
}

static int insertData(const char* s)
{
    sqlite3* DB;
    char* messageError;

    int exit = sqlite3_open(s, &DB);

    std::string sql("INSERT INTO HASH(FILENAME, MD5, SHA1, SHA256) VALUES('berkay', '" + md5 + "','" + sha1 + "','" + sha256 + "')");

    exit = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messageError);
    if (exit != SQLITE_OK)
    {
        std::cerr << "Error Insert" << std::endl;
        sqlite3_free(messageError);
    }
    else
        std::cout << "Records created successfully!" << std::endl;
    return 0;
}


static int selectData(const char* s)
{
    sqlite3* DB;
    int exit = sqlite3_open(s, &DB);

    std::string sql = "SELECT * FROM HASH";
    
    sqlite3_exec(DB, sql.c_str(), callback, NULL, NULL);

    return 0;

}

static int callback(void* NotUsed, int argc, char** argv, char** azColName)
{
    for (int i = 0; i < argc; i++)
        std::cout << azColName[i] << ": " << argv[i] << std::endl;

    std::cout << std::endl;

    return 0;
}