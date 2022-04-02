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
    std::shared_ptr<uint64_t> sender;
    std::shared_ptr<uint64_t> receiver;
    uint32_t amount;
    
    std::string encryptTr(uint8_t* key)
    { // decrypted hashed data should equal hash in mempool. TEST
        AES::AES256 aes256;
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver.get()[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return aes256.encrypt(transactionData, key);
    }
    
    // if owner of wallet(WalletAddress and keys)
    void dumptrdata(const std::map<std::shared_ptr<uint64_t>,std::vector<uint8_t*>>
                    walletData)
    {/* not tested */
        /* walletData = map to verify if owner of the wallet is requesting data dump
           std::shared_ptr<uint64_t> is WalletAddress and vector of uint8_t* is the string AES key
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
                if(sha512(AES256_ciphertext).get()[i] != key.get()[i]) {
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
            std::cout << std::hex << sender.get()[c];
        }
        std::cout << std::endl << std::endl;
        std::cout << "receiver\'s wallet address:\t";
        for(int c=0;c<8;c++) {
            std::cout << std::hex << receiver.get()[c];
        }
        std::cout << std::endl << std::endl;
        std::cout << "amount:\t" << amount;
        std::cout << std::endl << std::endl;
    }
    
    // A single hashed transaction data
    std::shared_ptr<uint64_t> Hash()
    {
        std::string transactionData = "";
        transactionData += "sender: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", receiver: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver.get()[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return sha512(transactionData);
    }
};

class WalletAddress
{
    public:
        std::pair<std::shared_ptr<uint64_t>, std::vector<uint8_t*>> 
        GenerateNewWalletAddress(std::string askForPrivKey="")
        {
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
            return {sha512(AES256_ciphertext), keys};
        }
};

class Address
{
    public:
        void verifyOwnerData(const std::map<std::shared_ptr<uint64_t>,
                             std::vector<uint8_t*>> walletData)
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
                    if(sha512(AES256_ciphertext).get()[i] != key.get()[i]) {
                        std::cout << "\nwallet data mismatch";
                        exit(EXIT_FAILURE);
                    } else {
                        std::cout << "\n\nwallet data verified\n\n";
                    }
                }
            }
        }
        
        void WalletAddressNotFound(std::shared_ptr<uint64_t> walletAddress,
                                   std::vector<uint8_t*> AESkeysWallet,
                                   std::string askForPrivKey="")
        {
            WalletAddress wallet_address = WalletAddress();
            std::cout << "No wallet address found!\n";
            std::cout << "Generating Wallet Address\n";
            auto [fst, snd] = wallet_address.GenerateNewWalletAddress(askForPrivKey);
            walletAddress = fst;
            AESkeysWallet = snd;
            std::cout << "Wallet Address Generated\nWallet Address:\t";
            for(int c=0;c<8;c++) {
                std::cout << std::hex << walletAddress.get()[c];
            }
            std::cout << "\n\ntrying again";
            
        }

        // if new transaction added to the Wallet
        void newTransaction(std::shared_ptr<uint64_t> sender,
                            std::shared_ptr<uint64_t> receiver, 
                            uint32_t amount, std::vector<std::shared_ptr<
                            uint64_t>> mempool, std::map<std::shared_ptr
                            <uint64_t>, std::vector<uint8_t*>> verifyInfo,
                            std::string sellorbuy, std::vector<uint8_t*> AESkeysTr,
                            std::vector<std::shared_ptr<uint64_t>> transactionhashes,
                            std::vector<std::string> ciphertexts, int32_t storedCrypto,
                            std::vector<uint8_t*> AESkeysWallet, std::shared_ptr
                            <uint64_t> walletAddress=nullptr,
                            std::string askForPrivKey="")
        {
            Address address = Address();
            if(walletAddress != nullptr) {
                verifyOwnerData(verifyInfo);
                if(sellorbuy=="sell") {
                    if(amount > storedCrypto) {
                        std::cout << "you do not own " << amount << ". Process failed";
                        exit(EXIT_FAILURE);
                    } else {
                        storedCrypto -= amount;
                    }
                } else if(sellorbuy=="buy") {
                    storedCrypto += amount;
                }
                struct Transaction trns{sender, receiver, amount};
                transactionhashes.push_back(trns.Hash());
                uint8_t* newAES_TrKey = nullptr;
                newAES_TrKey = new uint8_t[32];
                newAES_TrKey = GenerateAES256Key();
                ciphertexts.push_back(trns.encryptTr(newAES_TrKey));
                AESkeysTr.push_back(newAES_TrKey);
                mempool.push_back(transactionhashes[transactionhashes.size()]);
            } else {
                std::cout << "\nERR:\tWalletAddressNotFound\n";
                WalletAddressNotFound(walletAddress, AESkeysWallet, askForPrivKey);
                std::cout << "\nNew Wallet Address Created";
                newTransaction(sender, receiver, amount, mempool, verifyInfo,
                               sellorbuy, AESkeysTr, transactionhashes,
                               ciphertexts, storedCrypto, AESkeysWallet, nullptr);
                std::cout << "\nTransaction complete" << std::endl << std::endl;
            }
        }
};

struct Wallet {
    /* parameters to verify when owner of the wallet is modifying */
    // should be nullptr if WalletAddressNotFound
    std::shared_ptr<uint64_t> walletAddress;
    
    // can be empty if WalletAddressNotFound
    std::vector<uint8_t*> AESkeysWallet;  // length of 2
    
    /* verifyInfo includes AESkeysWallet in the first and second index. 
      If they don't match, don't change anything on the Wallet */
    std::map<std::shared_ptr<uint64_t>, std::vector<uint8_t*>> verifyInfo;
    void new_transaction(std::shared_ptr<uint64_t> sender,
                            std::shared_ptr<uint64_t> receiver, 
                            uint32_t amount, std::vector<std::shared_ptr<
                            uint64_t>> mempool, std::string sellorbuy,
                            std::vector<uint8_t*> AESkeysTr, std::vector<
                            std::shared_ptr<uint64_t>> transactionhashes,
                            std::vector<std::string> ciphertexts, int32_t
                            storedCrypto, std::string askForPrivKey="")

    {
        Address address = Address();
        address.newTransaction(sender, receiver, amount, mempool, verifyInfo, 
                               sellorbuy, AESkeysTr, transactionhashes, 
                               ciphertexts, storedCrypto, AESkeysWallet,
                               walletAddress, askForPrivKey);
    }
    void verifyOwnerData()
    {
        Address address = Address();
        address.verifyOwnerData(verifyInfo);
    }
    
    void WalletAddressNotFound(std::string askForPrivKey="")
    {
        Address address = Address();
        address.WalletAddressNotFound(walletAddress, AESkeysWallet, askForPrivKey);
    }
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
    std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]); // declare Merkle Root
    std::shared_ptr<uint64_t> walletAddress(new uint64_t[8]);
    std::vector<std::shared_ptr<uint64_t>> mempool; // declare mempool
    std::vector<std::shared_ptr<uint64_t>> walletAddresses; // All wallet addresses
    std::string blockchain_version = "1.0";
    struct Transaction trns{sha512("sender"), sha512("receiver"), 50000};
    struct Transaction trns1{sha512("sener"), sha512("receiver"), 54000};
    struct Transaction trns2{sha512("sender"), sha512("reciver"), 35600};
    struct Transaction trns3{sha512("nder"), sha512("receiver"), 50000};
    struct Transaction trns4{sha512("sender"), sha512("receiver"), 40000};
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
    /* TEST PoW MINE */
    uint8_t* AES_key_mining = new uint8_t[32];
    uint8_t* AES_key_mining1 = new uint8_t[32];
    uint8_t* AES_key_mining2 = new uint8_t[32];
    uint8_t* AES_key_mining3 = new uint8_t[32];
    AES_key_mining = GenerateAES256Key();
    AES_key_mining1 = GenerateAES256Key();
    AES_key_mining2 = GenerateAES256Key();
    AES_key_mining3 = GenerateAES256Key();
    std::map<std::string, uint8_t*> transactionsEnc;
    std::map<std::string, uint8_t*>::iterator it = transactionsEnc.begin(); ///// add all mempool transactions in order
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns.encryptTr(AES_key_miningA), AES_key_mining)); // 
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns1.encryptTr(AES_key_mining1), AES_key_mining1)); // 1
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns2.encryptTr(AES_key_mining2), AES_key_mining2)); // 2
    transactionsEnc.insert (it, std::pair<std::string, uint8_t*>
                            (trns3.encryptTr(AES_key_mining3), AES_key_mining3)); // 3
    
    /* TEST PoW MINE */
    std::vector<std::shared_ptr<uint64_t>> mempool2;
    mempool2.push_back(trns.Hash());
    mempool2.push_back(trns1.Hash());
    mempool2.push_back(trns2.Hash());
    mempool2.push_back(trns3.Hash());
    mempool2.push_back(trns4.Hash()); // 5 transactions
    mempool2.push_back(trns.Hash());
    mempool2.push_back(trns1.Hash());
    mempool2.push_back(trns2.Hash()); // 8 transactions
    mempool2.push_back(trns1.Hash()); // false from here
    mempool2.push_back(trns2.Hash()); // 10 transactions


    // block.data(mempool, transactionsEnc);
    auto [fst,snd] = wallet_address.GenerateNewWalletAddress();
    walletAddress = fst;
    walletAddresses.push_back(fst);
    std::cout << "\n\nline 339, main.cpp:\t";
    for(int c=0;c<8;c++) {
        // std::cout << std::hex << walletAddress.get()[c] << " ";
    }
    bool blockMined = false;
    if(blockMined == false) {
        std::tuple<std::shared_ptr<uint64_t>,std::string,uint32_t,uint64_t, 
               double,std::shared_ptr<uint64_t>, double, double>
        unverified_block_data = block.data(mempool2);
        uint32_t blockchainSize;
        uint64_t nonce;
        std::shared_ptr<uint64_t> prevBlockHash(new uint64_t[8]);
        std::string timestamp;
        double difficulty, nextBlockGenTime, avHashrate;
        std::tie(prevBlockHash, timestamp, blockchainSize, nonce, difficulty,
                 merkle_root,nextBlockGenTime, avHashrate) = unverified_block_data;
        auto [isblockmined,clean_mempool] = ProofofWork.mineBlock(transactionsEnc,
                                                                  nonce, difficulty,
                                                                  mempool,
                                                                  merkle_root);
        std::cout << "\nmempool cleaned";
        blockMined = isblockmined;
        
        if(blockMined) {
            std::cout << "\nblock mined successfully";
            std::cout << "\nrepresenting correct block in blockhain...\n";
            std::cout << block.data_str(clean_mempool,blockchain_version);
            std::cout << "\n\nblock added to blockchain";
            /* wrong mempool cannot have less than correct mempool since wrong
             * mempool has new false transaction */
        }
    }
    std::cout << "\nline 339, main.cpp complete";
    /* TEST walletAddress */
    std::map<std::shared_ptr<uint64_t>, std::vector<uint8_t*>> testMap;
    std::map<std::shared_ptr<uint64_t>, std::vector<uint8_t*>>::iterator
    itMap = testMap.begin();
    testMap.insert(itMap, std::pair<std::shared_ptr<uint64_t>, 
                   std::vector<uint8_t*>>(walletAddress, snd));
    struct Wallet TestWallet{walletAddress, snd, testMap};
    
    delete[] snd[0];
    delete[] snd[1];
    return 0;
}
