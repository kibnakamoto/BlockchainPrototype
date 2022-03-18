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
#include <tuple>
#include <map>
#include "bigInt.h"
#include "sha512.h"
#include "MerkleTree.h"
#include "AES.h" // Symmetrical Encryption
#include "block.h"

// 256-bit random number. AES key
uint8_t* GenerateAES256Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    uint8_t* key = nullptr;
    key = new uint8_t[32];
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
      std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<32-4;c++) {
        uint32_t tmp = distr(generator);
        key[c] = tmp>>24 & 0xff;
        key[c+1] = tmp>>16 & 0xff;
        key[c+2] = tmp>>8 & 0xff;
        key[c+3] = tmp & 0xff;
    }
    return key;
}


struct Transaction {
    uint64_t* sender = new uint64_t[8];
    uint64_t* receiver = new uint64_t[8];
    uint32_t amount;
    
    std::string encryptTr(uint8_t* key)
    {
        AES::AES256 aes256;
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
        return aes256.encrypt(transactionData, key);
    }
    
    // if owner of wallet(WalletAddress and keys)
    void dumptrdata(const std::map<uint64_t*,std::vector<uint8_t*>> walletData)
    {/* not tested */
        /* walletData = map to verify if owner of the wallet is requesting data dump
           uint64_t* is WalletAddress and vector of uint8_t* is the string AES key
           used as plain text and the AES key used as an AES key.
           walletData vector has length 2 and key used as key is first and 
           string key as uint8_t* is second
        */
        // useless function. Delete if not useful as reference
        std::cout << std::endl << std::endl;
        AES::AES256 aes256;
        std::string AESkeyStr = "";
        std::string AES256_ciphertext = "";
        for (auto const& [key, val] : walletData) {
            for(int c=0;c<32;c++) {
            AESkeyStr += std::to_string(val[1][c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
            for(int i=0;i<8;i++) {
                if(sha512(AES256_ciphertext)[i] != key[i]) {
                    std::cout << "wallet Data mismatch";
                    exit(EXIT_FAILURE);
                }
            }
            std::cout << std::endl << std::endl << "AES256 key:\t";
            for(int c=0;c<32;c++) {
                std::cout << val[1][c];
            }
            std::cout << std::endl << std::endl;
        }
        std::cout << "sender\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << sender[c];
        }
        std::cout << std::endl << std::endl;
        std::cout << "receiver\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << receiver[c];
        }
        std::cout << std::endl << std::endl;
        std::cout << "amount:\t" << amount;
        std::cout << std::endl << std::endl;
    }
    
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
    public:
        std::pair<uint64_t*, std::vector<uint8_t*>> 
        GenerateNewWalletAddress(std::string askForPrivKey="")
        { // make it a pair function that returns both aes key and ciphertext hash
            std::string AES256_ciphertext;
            IntTypes int_type = IntTypes();
            AES::AES256 aes256;
            uint8_t* AESkey = nullptr;
            AESkey = new uint8_t[32];
            AESkey = GenerateAES256Key(); // 32 bytes
            uint8_t* NewAESkey = nullptr;
            NewAESkey = new uint8_t[32];
            NewAESkey = GenerateAES256Key();
            std::string AESkeyStr = "";
            for(int c=0;c<32;c++) { /* plain text = new AES key in string */
                AESkeyStr += std::to_string(NewAESkey[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, AESkey);
            if (askForPrivKey == "dump AES-key") {
                std::cout << std::endl << "AES256 key:\t";
                for(int c=0;c<32;c++) {
                    std::cout << AESkey[c];
                }
                std::cout << std::endl << std::endl;
            }
            std::vector<uint8_t*> keys;
            keys.push_back(AESkey);
            keys.push_back(NewAESkey);
            return {int_type.avoidPtr(sha512("abc")), keys}; // 2a9ac94fa54ca49f
        }
};

union Wallet {
    // parameters to verify owner of the wallet is modifying
    static uint64_t* walletAddress; // should be nullptr if WalletAddressNotFound
    static std::vector<uint8_t*> AESkeysWallet; // can be empty if WalletAddressNotFound
    
    /* verifyInfo includes AESkeysWallet in the first and second index. If they don't match, don't change anything on the Wallet */
    static std::map<uint64_t*, std::vector<uint8_t*>> verifyInfo;
    class WA
    {
        protected:
            std::vector<uint8_t*> AESkeysTr;
            std::vector<std::string> ciphertexts;
            std::vector<uint64_t*> transactionhashes;
            int32_t storedCrypto = 0; // can be negative
        
        public:
            void verifyOwnerData(const std::map<uint64_t*,std::vector<uint8_t*>>
                                 walletData)
            {
                AES::AES256 aes256;
                std::string AESkeyStr = "";
                std::string AES256_ciphertext = "";
                for (auto const& [key, val] : walletData) {
                    for(int c=0;c<32;c++) {
                        AESkeyStr += std::to_string(val[1][c]);
                    }
                    AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
                    for(int i=0;i<8;i++) {
                        if(sha512(AES256_ciphertext)[i] != key[i]) {
                            std::cout << "\nwallet data mismatch";
                            exit(EXIT_FAILURE);
                        } else {
                            std::cout << "\n\nwallet data verified\n\n";
                        }
                    }
                }
            }
            
            void WalletAddressNotFound()
            {
                WalletAddress wallet_address = WalletAddress();
                std::cout << "No wallet address found!\n";
                std::cout << "Generating Wallet Address\n";
                auto [fst, snd] = wallet_address.GenerateNewWalletAddress();
                walletAddress = fst;
                AESkeysWallet = snd;
                std::cout << "Wallet Address Generated\nWallet Address:\t";
                for(int c=0;c<8;c++) {
                    std::cout << std::hex << walletAddress[c];
                }
                std::cout << "\n\ntrying again";
                
            }
            // append crypto to the wallet
            void appendCrypto(uint32_t amount)
            {
                if(walletAddress == nullptr) {
                    WalletAddressNotFound(); // if wallet not created
                } else {
                    verifyOwnerData(verifyInfo);
                }
                storedCrypto += amount;
            }
            
            void subtractCrypto(uint32_t amount)
            {
                verifyOwnerData(verifyInfo);
                if(amount > storedCrypto) {
                    std::cout << "you do not own " << amount << ". Process failed";
                    exit(EXIT_FAILURE);
                } else if(walletAddress == nullptr) {
                    std::cout << "\naccount not found\n";
                    exit(EXIT_FAILURE);
                } else {
                    storedCrypto -= amount;
                }
            }
            
            // if new transaction added to the Wallet
            void newTransaction(uint64_t* sender, uint64_t* receiver, 
                                uint32_t amount, std::vector<uint64_t*> 
                                mempool)
            {
                if(walletAddress != nullptr) {
                    verifyOwnerData(verifyInfo);
                    struct Transaction trns{sender, receiver, amount};
                    transactionhashes.push_back(trns.Hash());
                    storedCrypto -= amount;
                    uint8_t* newAES_TrKey = nullptr;
                    newAES_TrKey = new uint8_t[32];
                    newAES_TrKey = GenerateAES256Key();
                    ciphertexts.push_back(trns.encryptTr(newAES_TrKey));
                    AESkeysTr.push_back(newAES_TrKey);
                    mempool.push_back(transactionhashes[transactionhashes.size()]);
                } else {
                    std::cout << "\nERR:\tWalletAddressNotFound\n";
                    WalletAddressNotFound();
                    std::cout << "\nNew Wallet Address Created\n";
                    newTransaction(sender, receiver, amount, mempool);
                    std::cout << "\nTransaction complete";
                    std::cout << std::endl << std::endl;
                }
            }
    };
};

int main()
{
    /* need string hash values while comparing hashes */
    IntTypes int_type = IntTypes();
    WalletAddress wallet_address = WalletAddress();
    SHA512 hash = SHA512();
    Block block = Block();
    PoW ProofofWork = PoW();
    AES::AES128 aes128;
    AES::AES192 aes192;
    AES::AES256 aes256;
    uint64_t* merkle_root = new uint64_t[8]; // declare Merkle Root
    uint64_t* walletAddress = new uint64_t[8];
    std::vector<uint64_t*> mempool; // declare mempool
    std::vector<uint64_t*> walletAddresses; // All wallet addresses
    struct Transaction trns{int_type.avoidPtr(sha512("sender")),
                            int_type.avoidPtr(sha512("receiver")), // TODO: fix
                            50000};
    struct Transaction trns1{int_type.avoidPtr(sha512("sener")),
                            int_type.avoidPtr(sha512("receiver")), // TODO: fix
                            54000};
    struct Transaction trns2{int_type.avoidPtr(sha512("sender")),
                            int_type.avoidPtr(sha512("reciver")), // TODO: fix
                            35600};
    
    struct Transaction trns3{int_type.avoidPtr(sha512("nder")),
                            int_type.avoidPtr(sha512("receiver")), // TODO: fix
                            50000};
    struct Transaction trns4{int_type.avoidPtr(sha512("sender")),
                            int_type.avoidPtr(sha512("receiver")), // TODO: fix
                            40000};
    mempool.push_back(trns.Hash());
    /* TEST MERKLE_ROOT */
    mempool.push_back(trns1.Hash());
    mempool.push_back(trns2.Hash());
    mempool.push_back(trns3.Hash());
    mempool.push_back(trns4.Hash()); // 5 transactions
    mempool.push_back(trns.Hash());
    mempool.push_back(trns1.Hash());
    mempool.push_back(trns2.Hash()); // 8 transactions
    /* TEST MERKLE_ROOT */
    /* TEST POW MINE */
    uint8_t* AES_key_mining = new uint8_t[32];
    uint8_t* AES_key_mining1 = new uint8_t[32];
    uint8_t* AES_key_mining2 = new uint8_t[32];
    uint8_t* AES_key_mining3 = new uint8_t[32];
    AES_key_mining = GenerateAES256Key();
    AES_key_mining1 = GenerateAES256Key();
    AES_key_mining2 = GenerateAES256Key();
    AES_key_mining3 = GenerateAES256Key();
    std::map<std::string, uint8_t*> transactionsEnc;
    std::map<std::string, uint8_t*>::iterator it = transactionsEnc.begin();
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns.encryptTr(AES_key_mining), AES_key_mining)); // 
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns.encryptTr(AES_key_mining1), AES_key_mining1)); // 1
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns.encryptTr(AES_key_mining2), AES_key_mining2)); // 2
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns.encryptTr(AES_key_mining3), AES_key_mining3)); // 3

    ProofofWork.mineBlock(transactionsEnc);
    /* TEST POW MINE */
    block.data(mempool);
    auto [fst,snd] = wallet_address.GenerateNewWalletAddress();
    walletAddress = fst;
    walletAddresses.push_back(fst);
    delete[] snd[0];
    delete[] snd[1];
    for(int c=0;c<8;c++) {
        // std::cout << std::hex << walletAddress[c] << " ";
        std::cout << std::hex << trns.Hash()[c] << " ";
    }
    return 0;
}
