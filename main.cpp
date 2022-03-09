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
        // 512-bit random number. ECC private key
        uint64_t* GeneratePrivateKey(uint64_t* private_key)
        {
            std::random_device randDev;
            std::mt19937_64 gen(randDev());
            std::uniform_int_distribution<uint64_t> randUint64;
            for(int c=0;c<8;c++) {
                private_key[c] = randUint64(gen);
            }
            return private_key;
        }
    public:
        uint64_t* GenerateNewWalletAddress(uint64_t* public_key,
                                           std::string askForPrivKey="")
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            uint64_t private_key[8];
            GeneratePrivateKey(private_key); // 512-bit
            /* TODO:
            A bitcoin wallet contains a collection of key pairs, each consisting
            of a private key and a public key. The private key (k) is a number,
            usually picked at random. From the private key, we use elliptic
            curve multiplication, a one-way cryptographic function, to generate
            a public key (K). From the public key (K), we use a one-way 
            cryptographic hash function to generate a bitcoin address (A)
            */
            if (askForPrivKey == "dumpprivkey") { // print as char
                std::cout << std::endl << "private key:\t";
                uint8_t private_key_8_bit[64];
                for(int c=0;c<8;c++) {
                    private_key_8_bit[c*8] = private_key[c]>>56 & 0xff;
                    private_key_8_bit[c*8+1] = private_key[c]>>48 & 0xff;
                    private_key_8_bit[c*8+2] = private_key[c]>>40 & 0xff;
                    private_key_8_bit[c*8+3] = private_key[c]>>32 & 0xff;
                    private_key_8_bit[c*8+4] = private_key[c]>>24 & 0xff;
                    private_key_8_bit[c*8+5] = private_key[c]>>16 & 0xff;
                    private_key_8_bit[c*8+6] = private_key[c]>>8 & 0xff;
                    private_key_8_bit[c*8+7] = private_key[c] & 0xff;
                }
                // convert uint8_t to char value
                for(int c=0;c<64;c++) {
                    std::cout << private_key_8_bit[c];
                }
            }
            
            return nullptr; // hash.sha512_single_ptr(public_key);
        }
        
        protected:
            std::vector<uint64_t*> private_keys;
            std::vector<uint64_t*> public_keys;
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
    uint64_t public_key[8];
    std::vector<uint64_t*> mempool; // declare mempool
    struct SingleMempoolHash transaction{int_type.avoidPtr(sha512("sender"),
                                                           senderPtr),
                                         int_type.avoidPtr(sha512("receiver"),
                                                           receiverPtr),
                                         50000};
    mempool.push_back(transaction.Hash());
    merkle_tree.MerkleRoot(mempool, merkle_root);
    wallet_address.GenerateNewWalletAddress(sha512("public_key"),
                                            "don\'t dumpprivkey");
    uint8_t aeskey[32];
    for(int c=0;c<32;c++) {
        aeskey[c] = 0x00U;
    }
    aes256.encrypt("msg", aeskey);
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
