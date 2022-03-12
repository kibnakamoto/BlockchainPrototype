/*
* Author: Taha Canturk
*  Github: kibnakamoto
*   Start Date: Feb 9, 2022
*    Finish Date: N/A
*
* This implementation only works for C++ version 17 or above. 
* C++ 14 also works but gives warning
* 
*/

#include <iostream>
#include <string>
#include <random>
#include <time.h>
#include "bigInt.h"
#include "sha512.h"
#include "MerkleTree.h"
#include "AES.h" // Symmetrical Encryption

struct SingleMempoolHash {
    uint64_t* sender = new uint64_t[8];
    uint64_t* receiver = new uint64_t[8];
    uint32_t amount;
    
    // A single hashed transaction data
    uint64_t* Hash()
    { /* if parameter is a raw pointer instead of array. It's wrong */
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return sha512(transactionData);
    }
};

class WalletAddress
{
    private:
        // 512-bit random number. half of AES private key
        uint8_t* GenerateAES256Key(uint8_t* key)
        {
            /* random byte using Mersenne Twister. Not recommended for 
               cryptography but couldn't find a cryptographic random byte generator */
            
            std::random_device randDev;
            std::mt19937 generator(randDev() ^ time(NULL));
              std::uniform_int_distribution<uint32_t> distr;
            for(int c=0;c<32-4;c++) {
                key[c] = distr(generator)>>24 & 0xff;
                key[c+1] = distr(generator)>>16 & 0xff;
                key[c+2] = distr(generator)>>8 & 0xff;
                key[c+3] = distr(generator) & 0xff;
            }
            return key;
        }
    public:
        uint64_t* GenerateNewWalletAddress(std::string askForPrivKey="")
        {
            std::string AES256_ciphertext;
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            AES::AES256 aes256;
            uint8_t* AESkey = nullptr;
            AESkey = new uint8_t[32];
            GenerateAES256Key(AESkey); // 32 bytes
            std::string AESkeyStr = "";
            for(int c=0;c<32;c++) { /* plain text = Generated key in string */
                AESkeyStr += std::to_string(AESkey[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, AESkey);
            if (askForPrivKey == "dump AES-key") {
                std::cout << std::endl << "AES256 key:\t";
                for(int c=0;c<32;c++) {
                    std::cout << AESkey[c];
                }
            }
            return sha512(AES256_ciphertext);
        }
        
        protected:
            std::vector<uint64_t*> private_keys;
            std::vector<uint64_t*> AESkeys;
            struct wallet
            {
                
            };
};

int main()
{
    /* need string hash values while comparing hashes */
    IntTypes int_type = IntTypes();
    MerkleTree merkle_tree = MerkleTree();
    WalletAddress wallet_address = WalletAddress();
    AES::AES128 aes128;
    AES::AES192 aes192;
    AES::AES256 aes256;
    uint64_t SingleMempoolHash64[8];
    uint64_t merkle_root[8]; // declare Merkle Root
    uint64_t senderPtr[8];
    uint64_t receiverPtr[8];
    uint64_t* walletAddress = nullptr;
    walletAddress = new uint64_t[8];
    std::vector<uint64_t*> mempool; // declare mempool
    struct SingleMempoolHash transaction{int_type.avoidPtr(sha512("sender"),
                                                           senderPtr),
                                         int_type.avoidPtr(sha512("receiver"),
                                                           receiverPtr),
                                         50000};
    mempool.push_back(transaction.Hash());
    merkle_tree.MerkleRoot(mempool, merkle_root);
    walletAddress = wallet_address.GenerateNewWalletAddress();
    // 8x64 bit transaction hash into 4x128 transaction hash
    auto [fst, snd, trd, frd] = int_type.__uint512_t(SingleMempoolHash64);
    for(int c=0;c<0;c++) {
        fst;
        snd;
        trd;
        frd;
    }
    return 0;
}
