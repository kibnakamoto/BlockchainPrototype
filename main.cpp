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
#include "AES.h"
#include "block.h"

// 256-bit random number. AES key
std::shared_ptr<uint8_t> generateAES256Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[32]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<8;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c] = tmp>>24 & 0xff;
        key.get()[c*4+1] = tmp>>16 & 0xff;
        key.get()[c*4+2] = tmp>>8 & 0xff;
        key.get()[c*4+3] = tmp & 0xff;
    }
    return key;
}

// 192-bit random number. AES key
std::shared_ptr<uint8_t> generateAES192Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[24]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<8;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c*3+1] = tmp>>16 & 0xff;
        key.get()[c*3+2] = tmp>>8 & 0xff;
        key.get()[c*3+3] = tmp & 0xff;
    }
    return key;
}

// 128-bit random number. AES key
std::shared_ptr<uint8_t> generateAES128Key()
{
    /* random byte using Mersenne Twister. Not recommended for 
       cryptography but couldn't find a cryptographic random byte generator */
    std::shared_ptr<uint8_t> key(new uint8_t[16]);
    std::random_device randDev;
    std::mt19937 generator(randDev() ^ time(NULL));
     std::uniform_int_distribution<uint32_t> distr;
    for(int c=0;c<8;c++) {
        uint32_t tmp = distr(generator);
        key.get()[c*2] = tmp>>8 & 0xff;
        key.get()[c*2+1] = tmp & 0xff;
    }
    return key;
}

// for user input in UI
template<class T>
std::string aesKeyToStr(std::shared_ptr<T> key, uint32_t keysize=32)
{
    std::stringstream ss;
    for(int c=0;c<keysize;c++) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (short)key.get()[c];
    }
    return ss.str();
}

// reverse aeskey_tostr function for use in UI, default key size is for aes256
template<class T>
std::shared_ptr<T> aesKeyToSPtr(std::string strKey, uint32_t keysize=32)
{
    if(strKey.length() != keysize*2) {
        std::cout << "length of key doesn't match required algorithm key size: "
                  << keysize;
        exit(EXIT_FAILURE);
    }
    std::shared_ptr<T> key(new T[keysize]);
    std::string bytes="";
    for(int c=0;c<keysize;c++) {
        bytes += strKey.substr(c*2,2);
        if (c<keysize-1) {
            bytes += " ";
        }
    }
    std::istringstream hexCharsStream(bytes);
    unsigned int ch;
    int i=0;
    while (hexCharsStream >> std::hex >> ch)
    {
        key.get()[i] = ch;
        i++;
    }
    return key;
}

// wallet address has to be 512-bits at all conditions and in hex format
std::shared_ptr<uint64_t> usrInWallet512(std::string walletAddress)
{
    if(walletAddress.length() != 128) {
        std::cout << "input length not 64 bytes";
        exit(EXIT_FAILURE);
    }
    std::shared_ptr<uint64_t> hash(new uint64_t[8]);
    for(int c=0;c<8;c++) {
        std::string substr = "0x" + walletAddress.substr(c*16,16);
        hash.get()[c] = std::stoul(substr, nullptr, 16);
    }
    return hash;
}



struct Transaction {
    // sender and receiver can be reversed and are only variable names
    std::shared_ptr<uint64_t> sender;
    std::shared_ptr<uint64_t> receiver;
    uint32_t amount;
    
    std::string encryptTr(std::shared_ptr<uint8_t> key,std::string buysOrSell)
    {
        AES::AES256 aes256;
        std::string transactionData = "";
        if(buysOrSell == "buy") {
            buysOrSell += "s"; // make it 4 chars
        }

        transactionData += buysOrSell + ", ";
        transactionData += "wallet one: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", wallet two: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver.get()[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        
        return aes256.encrypt(transactionData, key);
    }
    
    // to delete padding from decrypted message
    uint64_t length()
    {
        std::string transactionData = "";
        // for length, buy or sell isn't required and just use the right amount of chars
        // use buys for buy so that its the same length
        transactionData += "bosc, ";
        transactionData += "wallet one: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", wallet two: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(receiver.get()[c]);
        }
        transactionData += ", amount: " + std::to_string(amount);
        return transactionData.length();
    }
    
    // time since epoch to orginize transactions by timestamp
    __uint128_t getTrTimestamp()
    {
        return std::chrono::duration_cast<std::chrono::duration<
               __uint128_t>>(std::chrono::duration_cast<std::chrono::milliseconds
               >(std::chrono::system_clock::now().time_since_epoch())).count();
    }
    
    // if owner of wallet(WalletAddress and keys)
    void dumptrdata(const std::map<std::shared_ptr<uint64_t>,std::vector<
                    std::shared_ptr<uint8_t>>> walletData)
    {
        /* walletData = map to verify if owner of the wallet is requesting data dump
         * std::shared_ptr<uint64_t> is WalletAddress and vector of std::shared_ptr
         * <uint8_t> is the string AES key used as plain text and the AES key
         * used as an AES key. walletData vector has length 2 and key used as
         * key is first and string key as std::shared_ptr<uint8_t> is second
         */
        // useless function. Delete if not useful as reference
        std::cout << std::endl << std::endl;
        AES::AES256 aes256;
        std::string AESkeyStr = "";
        std::string AES256_ciphertext = "";
        for (auto const& [key, val] : walletData) {
            for(int c=0;c<32;c++) {
            AESkeyStr += std::to_string(val[1].get()[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
            for(int i=0;i<8;i++) {
                if(sha512(AES256_ciphertext).get()[i] != key.get()[i]) {
                    std::cout << "wallet Data mismatch";
                    exit(EXIT_FAILURE);
                }
            }
            std::cout << std::endl << std::endl << "AES256 key 1:\t";
            for(int c=0;c<32;c++) {
                std::cout << std::hex << (short)val[0].get()[c] << " ";
            }
            
            std::cout << std::endl << std::endl << "AES256 key 2:\t";
            for(int c=0;c<32;c++) {
                std::cout << std::hex << (short)val[1].get()[c] << " ";
            }
            std::cout << std::endl << std::endl;
        }
        std::cout << "your wallet address:\t";
        std::cout << to8_64_str(sender);
        std::cout << std::endl;
        std::cout << "external wallet address:\t";
        std::cout << to8_64_str(receiver);
        std::cout << std::endl;
        std::cout << "amount:\t" << std::dec << amount;
        std::cout << std::endl << std::endl;
    }
    
    // A single hashed transaction data
    std::shared_ptr<uint64_t> Hash(std::string buysOrSell)
    {
        std::string transactionData = "";
        if(buysOrSell == "buy") {
            buysOrSell += "s"; // make it 4 chars
        }
        transactionData += buysOrSell + ", ";
        transactionData += "wallet one: ";
        for(int c=0;c<8;c++) {
            transactionData += std::to_string(sender.get()[c]);
        }
        transactionData += ", wallet two: ";
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
        std::pair<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> 
        GenerateNewWalletAddress(std::string askForPrivKey="")
        {
            std::string AES256_ciphertext;
            IntTypes int_type = IntTypes();
            AES::AES256 aes256;
            std::shared_ptr<uint8_t> AESkey(new uint8_t[32]);
            AESkey = generateAES256Key(); // 32 bytes
            std::shared_ptr<uint8_t> NewAESkey(new uint8_t[32]);
            NewAESkey = generateAES256Key();
            std::string AESkeyStr = "";
            for(int c=0;c<32;c++) { /* plain text = new AES key in string */
                AESkeyStr += std::to_string(NewAESkey.get()[c]);
            }
            AES256_ciphertext = aes256.encrypt(AESkeyStr, AESkey);
            if (askForPrivKey == "dump aes256-key") {
                std::cout << std::endl << "AES256 key 1:\t" << aesKeyToStr<uint8_t>(AESkey);
                std::cout << std::endl << std::endl;
                std::cout << "AES256 key 2:\t" << aesKeyToStr<uint8_t>(NewAESkey);
                std::cout << std::endl << std::endl;

            }
            std::vector<std::shared_ptr<uint8_t>> keys;
            keys.push_back(AESkey);
            keys.push_back(NewAESkey);
            return {sha512(AES256_ciphertext), keys};
        }
        
        // for UI input
        void verifyInputWallet(std::vector<std::shared_ptr<uint64_t>> walletAddresses,
                               std::shared_ptr<uint64_t> walletAddress)
        {
                            // find if walletAddress in vector walletAddresses
                bool walletAValid;
                for(int i=0;i<walletAddresses.size();i++) {
                    std::vector<bool> validity;
                    for(int c=0;c<8;c++) {
                        if(walletAddresses[i].get()[c] == walletAddress.get()[c]) {
                            validity.push_back(true);
                        } else {
                            validity.push_back(false);
                        }
                    }
                    // find wheter walletAddress is true or false
                    if(std::find(validity.begin(), validity.end(), false) !=
                       validity.end()) {
                        walletAValid = false;
                        validity.clear();
                    } else {
                        walletAValid = true;
                        break; // stops if true, continues to search if false
                    }
                }
                
                // terminate or not
                if(walletAValid) {
                    std::cout << "\nwallet address verified";
                } else {
                    std::cout << "\nerror: wallet address doesn't exist";
                    exit(EXIT_FAILURE);
                }
        }
};

class Address
{
    public:
        void verifyOwnerData(const std::map<std::shared_ptr<uint64_t>,
                             std::vector<std::shared_ptr<uint8_t>>> walletData)
        {
            AES::AES256 aes256;
            std::string AESkeyStr = "";
            std::string AES256_ciphertext;
            for (auto const& [key, val] : walletData) {
                for(int c=0;c<32;c++) {
                    AESkeyStr += std::to_string(val[1].get()[c]);
                }
                AES256_ciphertext = aes256.encrypt(AESkeyStr, val[0]);
                for(int i=0;i<8;i++) {
                    if(sha512(AES256_ciphertext).get()[i] != key.get()[i]) {
                        std::cout << "\nwallet data mismatch";
                        exit(EXIT_FAILURE);
                    } else {
                        goto stop;
                    }
                }
            }
            stop:
                std::cout << "\n\nwallet data verified\n\n";
        }
        
        std::pair<std::shared_ptr<uint64_t>,std::vector<std::shared_ptr<uint8_t>>>
        WalletAddressNotFound(std::vector<std::shared_ptr<uint8_t>> AESkeysWallet,
                              std::string askForPrivKey="")
        {
            WalletAddress wallet_address = WalletAddress();
            std::shared_ptr<uint64_t> walletAddress(new uint64_t[8]);
            std::cout << "No wallet address found!\n";
            std::cout << "Generating Wallet Address\n";
            auto [fst, snd] = wallet_address.GenerateNewWalletAddress(askForPrivKey);
            walletAddress = fst;
            AESkeysWallet = snd;
            std::cout << "Wallet Address Generated\nWallet Address:\t";
            std::cout << std::hex << to8_64_str(walletAddress);
            std::cout << "\ntrying again";
            return {walletAddress,AESkeysWallet};
            
        }

        // if new transaction added to the Wallet
        std::pair<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>>
        newTransaction(std::shared_ptr<uint64_t> sender, std::shared_ptr<uint64_t>
                       receiver, uint32_t amount, std::vector<std::shared_ptr<
                       uint64_t>> &mempool, std::map<std::shared_ptr
                       <uint64_t>, std::vector<std::shared_ptr<uint8_t>>>
                       verifyInfo, std::string sellorbuy, std::vector
                       <std::shared_ptr<uint64_t>>& transactionhashes,
                       std::map<std::string, std::shared_ptr<uint8_t>>&
                       transactionsEnc, int32_t& storedCrypto, std::vector<std::
                       shared_ptr<uint8_t>> AESkeysWallet,std::shared_ptr<uint64_t>
                       walletAddress=nullptr,std::string askForPrivKey="")
        {
            Address address = Address();
            if(walletAddress != nullptr) {
                verifyOwnerData(verifyInfo);
                if(sellorbuy=="sell") {
                    if(amount > storedCrypto) {
                        std::cout << "you do not own " << std::dec << amount
                                  << ". Process failed";
                        sender = walletAddress;
                        exit(EXIT_FAILURE);
                    } else {
                        storedCrypto -= amount;
                        std::cout << "\nyou sold " << std::dec << amount
                                  << "\nyou now own "
                                  << storedCrypto;
                    }
                } else if(sellorbuy=="buy") {
                    
                    storedCrypto += amount;
                    std::cout << "\n"  << std::dec << amount
                              << " bought.\nyou now own " << storedCrypto
                              << "\n\n";
                    receiver = walletAddress;
                }
                
                struct Transaction trns{sender, receiver, amount};
                transactionhashes.push_back(trns.Hash(sellorbuy));
                std::shared_ptr<uint8_t> newAES_TrKey(new uint8_t[32]);
                newAES_TrKey = generateAES256Key();
                std::map<std::string, std::shared_ptr<uint8_t>>::iterator
                it = transactionsEnc.begin();
                transactionsEnc.insert(it, std::pair<std::string, std::shared_ptr
                                       <uint8_t>> (trns.encryptTr(newAES_TrKey, sellorbuy),
                                                   newAES_TrKey));
                mempool.push_back(transactionhashes[transactionhashes.size()-1]);
            } else {
                std::cout << "\nERR:\tWalletAddressNotFound\n";
                auto [fst, snd] = WalletAddressNotFound(AESkeysWallet,
                                                        askForPrivKey);
                walletAddress = fst;
                AESkeysWallet = snd;
                std::cout << "\nNew Wallet Address Created";
                newTransaction(sender, receiver, amount, mempool, verifyInfo,
                               sellorbuy, transactionhashes, transactionsEnc,
                               storedCrypto, AESkeysWallet, walletAddress);
                std::cout << "\nTransaction complete" << std::endl << std::endl;
            }
            return {walletAddress,AESkeysWallet};
        }
};

struct Wallet {
    /* parameters to verify when owner of the wallet is modifying */
    // should be nullptr if WalletAddressNotFound
    std::shared_ptr<uint64_t> walletAddress;
    
    // can be empty if WalletAddressNotFound
    std::vector<std::shared_ptr<uint8_t>> &AESkeysWallet;  // length of 2
    
    /* verifyInfo includes AESkeysWallet in the first and second index. 
      If they don't match, don't change anything on the Wallet */
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> verifyInfo;
    
    std::pair<std::shared_ptr<uint64_t>,std::vector<std::shared_ptr<uint8_t>>>
    new_transaction(std::shared_ptr<uint64_t> sender, std::shared_ptr<uint64_t>
                    receiver, uint32_t amount, std::vector<std::shared_ptr<
                    uint64_t>> mempool, std::string sellorbuy, std::vector<
                    std::shared_ptr<uint64_t>> transactionhashes,
                    std::map<std::string, std::shared_ptr<uint8_t>>&
                    transactionsEnc, int32_t storedCrypto, std::string
                    askForPrivKey="")
    {
        Address address = Address();
        auto [fst,snd] = address.newTransaction(sender, receiver, amount, mempool,
                                                verifyInfo, sellorbuy,
                                                transactionhashes, transactionsEnc,
                                                storedCrypto, AESkeysWallet,
                                                walletAddress, askForPrivKey);
        return {fst,snd};
    }
    void verifyOwnerData()
    {
        Address address = Address();
        address.verifyOwnerData(verifyInfo);
    }
    
    std::shared_ptr<uint64_t> WalletAddressNotFound(std::string askForPrivKey="")
    {
        Address address = Address();
        auto [fst,snd] = address.WalletAddressNotFound(AESkeysWallet, askForPrivKey);
        AESkeysWallet = snd;
        return fst;
        
    }
};

/* UI */
struct userData
{
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> walletMap;
    std::map<std::string,std::shared_ptr<uint8_t>> &transactions;
    std::vector<std::shared_ptr<uint64_t>> &transactionhashesW;
    std::vector<int32_t> &trnsLengths;
    
    int32_t setBalance()
    {
        std::string plaintext;
        AES::AES256 aes256;
        int32_t storedCrypto=0; // set to zero and recalculate
        for(auto const [ciphertext, b32key] : transactions) {
            plaintext = aes256.decrypt(ciphertext,b32key);
            std::string str_amount = "";
            size_t index = plaintext.find("amount: ");
            int lenIndex;
            
            // delete padding caused by encryption
            // check which length creates correct hash
            for(int c=0;c<trnsLengths.size();c++) {
                plaintext.erase(trnsLengths[c],plaintext.length()-trnsLengths[c]);
                std::shared_ptr<uint64_t> hash = sha512(plaintext);
                for(int i=0;i<transactionhashesW.size();i++) {
                    for(int j=0;j<8;j++)
                        if(transactionhashesW[i].get()[j] == hash.get()[j]) {
                            lenIndex = c;
                            goto stop;
                        }
                }
                stop:
                    for(int k=lenIndex;k<plaintext.length();k++) {
                        str_amount += plaintext[k];
                    }
                    // calculate wallet balance
                    int32_t amount = static_cast<int32_t>(std::stoul(str_amount));
                    if(plaintext.starts_with("buys")) {
                        storedCrypto += amount;
                    } else if(plaintext.starts_with("sell")) {
                        storedCrypto -= amount;
                    }
            }
        }
        return storedCrypto;
    }
};

/* GUI, not for UI */
struct userDatabase : public userData
{
    
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
    bool blockMined = false;
    /* TODO: add UI for wallet address creation, buy, sell, verify, login, 
     * sign-in, dump wallet data, allow manual encryption for wallet 
     * address and automatic encryption for wallet data, only allow login and
     * data decryption if database found user info match. No need for GUI yet.
     */
    
    /* TEST PoW MINE */
    // struct Transaction trns{sha512("sender"), sha512("receiver"), 50000};
    // struct Transaction trns1{sha512("sener"), sha512("receiver"), 54000};
    // struct Transaction trns2{sha512("sender"), sha512("reciver"), 35600};
    // struct Transaction trns3{sha512("nder"), sha512("receiver"), 50000};
    // struct Transaction trns4{sha512("sender"), sha512("receiver"), 40000};
    // mempool.push_back(trns.Hash());
    // mempool.push_back(trns1.Hash());
    // mempool.push_back(trns2.Hash());
    // mempool.push_back(trns3.Hash());
    // mempool.push_back(trns4.Hash()); // 5 transactions
    // mempool.push_back(trns.Hash());
    // mempool.push_back(trns1.Hash());
    // mempool.push_back(trns2.Hash()); // 8 transactions
    // std::shared_ptr<uint8_t> AES_key_mining(new uint8_t[32]);
    // std::shared_ptr<uint8_t> AES_key_mining1(new uint8_t[32]);
    // std::shared_ptr<uint8_t> AES_key_mining2(new uint8_t[32]);
    // std::shared_ptr<uint8_t> AES_key_mining3(new uint8_t[32]);
    // std::shared_ptr<uint8_t> AES_key_mining4(new uint8_t[32]);
    // AES_key_mining = generateAES256Key();
    // AES_key_mining1 = generateAES256Key();
    // AES_key_mining2 = generateAES256Key();
    // AES_key_mining3 = generateAES256Key();
    // AES_key_mining4 = generateAES256Key();
    // std::map<std::string, std::shared_ptr<uint8_t>> transactionsEnc;
    // std::map<std::string, std::shared_ptr<uint8_t>>::iterator it = transactionsEnc.begin();
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns.encryptTr(AES_key_mining), AES_key_mining)); // 
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns1.encryptTr(AES_key_mining1), AES_key_mining1)); // 1
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns2.encryptTr(AES_key_mining2), AES_key_mining2)); // 2
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns3.encryptTr(AES_key_mining3), AES_key_mining3)); // 3
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns4.encryptTr(AES_key_mining4), AES_key_mining4)); // 4
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns.encryptTr(AES_key_mining), AES_key_mining)); // 
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns1.encryptTr(AES_key_mining1), AES_key_mining1)); // 1
    // transactionsEnc.insert (it, std::pair<std::string, std::shared_ptr<uint8_t>>
    //                         (trns2.encryptTr(AES_key_mining2), AES_key_mining2)); // 2
    // std::vector<std::shared_ptr<uint64_t>> mempool2;
    // mempool2.push_back(trns.Hash());
    // mempool2.push_back(trns1.Hash());
    // mempool2.push_back(trns2.Hash());
    // mempool2.push_back(trns3.Hash());
    // mempool2.push_back(trns4.Hash()); // 5 transactions
    // mempool2.push_back(trns.Hash());
    // mempool2.push_back(trns1.Hash());
    // mempool2.push_back(trns2.Hash()); // 8 transactions
    // mempool2.push_back(trns1.Hash()); // false from here
    // mempool2.push_back(trns2.Hash());
    
    /* UI */
    std::string newUserIn;
    std::vector<std::string> listOfCommands {"help", "-help", "help-all", "create-wa",
                                             "buy","sell", "e-wallet-aes256",
                                             "e-wallet-aes128","e-wallet-aes192",
                                             "e-wallet-aes256-genkey",
                                             "e-wallet-aes192-genkey",
                                             "e-wallet-aes128-genkey",
                                             "d-wallet-aes256","d-wallet-aes128",
                                             "d-wallet-aes192",
                                             "get p-w key", "get p-trns key",
                                             "send", "del-wallet","exit","quit"
                                             "burn", "hash-sha512","enc-aes128-genkey",
                                             "enc-aes192-genkey","enc-aes256-genkey",
                                             "enc-aes128", "enc-aes192",
                                             "enc-aes256","dec-aes128", "dec-aes192",
                                             "dec-aes256","get blockchain",
                                             "get myahr", "get block-hash", 
                                             "get block-nonce",
                                             "get block-timestamp",
                                             "get block-merkle root",
                                             "get block-difficulty", "get block-ahr",
                                             "get nblocktime", "get blockchain-size",
                                             "get version", "get mempool",
                                             "enc-algs", "start mine", "end mine",
                                             "dump-wallet512", "dump-w-aes256k", "get tr-target",
                                             "get tr-hash", "get tr-ciphertext",
                                             "get tr-timestamp", "dump all-trnsData",
                                             "dump trnsData", "get blockchain-ahr",
                                             "get block-target"};
    std::vector<std::string> commandDescriptions
    {"help: show basic commands with descriptions",
     "-help: for command description, put after another command",
     "help-all: show all commands with description",
     "create-wa: generate new wallet address",
     "buy: buy an amount, must specify amount after typing buy",
     "sell: sell an amount, must specify amount after typing sell",
     "e-wallet-aes128: encrypt wallet with aes256, do not provide wallet address here, provide key",
     "e-wallet-aes192: encrypt wallet with aes192, do not provide wallet address here, provide key",
     "e-wallet-aes256: encrypt wallet with aes256, do not provide wallet address here, provide key",
     "e-wallet-aes128-genkey: encrypt wallet with aes256, do not provide wallet" +
     std::string("address here, do not provide key"),
     "e-wallet-aes192-genkey: encrypt wallet with aes192, do not provide wallet" +
     std::string(" address here, do not provide key"),
     "e-wallet-aes256-genkey: encrypt wallet with aes256, do not provide wallet" +
     std::string(" address here, do not provide key"),
     "d-wallet-aes128: decrypt wallet using aes128, provide key",
     "d-wallet-aes192: decrypt wallet using aes192, provide key",
     "d-wallet-aes256: decrypt wallet using aes256, provide key",
     "get p-w key: request private wallet key", "get p-trns key request single" +
     std::string(" transaction key, provide transaction index in wallet"),
     "send: send to another wallet address, provide wallet address and amount",
     "del-wallet: delete your wallet address, make sure wallet is empty before" +
     std::string(" doing so, wallet components will be deleted and cannot be brought back"),
     "exit: will terminate and exit program",
     "quit: will terminate and exit program",
     "burn [amount]: burn an amount of crypto(send to dead wallet address), provide amount",
     "hash-sha512 [input]: hash input with sha512",
     "enc-aes128-genkey [input,key]: encrypt input with aes128, key is generated for you",
     "enc-aes192-genkey [input,key]: encrypt input with aes192, key is generated for you",
     "enc-aes256-genkey [input,key]: encrypt input with aes256, key is generated for you",
     "enc-aes128 [input,key]: encrypt input with aes128, use own key in decimal format",
     "enc-aes192 [input,key]: encrypt input with aes192, use own key in decimal format",
     "enc-aes256 [input,key]: encrypt input with aes256, use own key in decimal format",
     "dec-aes128 [input,key]: decrypt ciphertext with aes128, provide key",
     "dec-aes192 [input,key]: decrypt ciphertext with aes192, provide key",
     "dec-aes256 [input,key]: decrypt ciphertext with aes256, provide key",
     "get myahr: print my average hashrate",
     "get blockchain: prints all blocks in blockchain",
     "get block-hash [block index]: get block hash, provide index",
     "get block-nonce [block index]: get block nonce, provide index",
     "get block-timestamp [block index]: get block timestamp, provide index",
     "get block-merkle root [block index]: get merkle root of block, provide index",
     "get block-difficulty [block index]: get difficulty of block, provide index",
     "get block-ahr [block index]: get average hash rate of block miners, provide index",
     "get nblocktime: get next block generation time",
     "get blockchain-size: print amounts of blocks in blockchain",
     "get version: get blockchain version",
     "get mempool: print verified mempool hashes in current block",
     "enc-algs: available encryption/decryption algorithms",
     "start mine: start mining", "end mine: end mining",
     "dump-wallet512: dump 512-bit wallet address as decimal",
     "dump-w-aes256k: dump 32 byte wallet key", // after this is not in version 1
     "get tr-target: print transaction target",
     "get tr-hash: print transaction hash",
     "get tr-ciphertext [trns index]: print transaction ciphertext",
     "get tr-timestamp [trns index]: print transaction timestamp",
     "dump all-trnsData: dump all transaction data in wallet",
     "dump trnsData [trns index]: dump single transaction data, provide transaction index",
     "get blockchain-ahr: get average hashrate over all blockchain",
     "get block-target [block index]: get block target hash, provide index"};
    std::string userInput = "";
    // std::cout << "for basic command list, input \"help\"\n"
    //           << "for all commands, input \"help-all\"\n";
    std::map<std::string,std::shared_ptr<uint8_t>> transactions;
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> walletMap;
    std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>>::iterator
    itWalletMap = walletMap.begin();
    std::vector<std::shared_ptr<uint8_t>> userAESmapkeys;
    std::vector<std::shared_ptr<uint8_t>> AESkeysTr;
    std::vector<int32_t> trnsLengths;
    
    // TODO: make dump command for ciphertexts listed below if data is encrypted
    std::string ciphertextW = ""; // wallet
    std::string ciphertextK1 = ""; // key1
    std::string ciphertextK2 = ""; // key2 
    std::string usedEncAlg;
    
    // transaction list in wallet
    std::vector<std::shared_ptr<uint64_t>> transactionhashesW;
    
    std::shared_ptr<uint64_t> secondWallet(new uint64_t[8]);
    
    if(userInput == "help") {
        for(int c=0;c<18;c++)
            std::cout << commandDescriptions[c] << "\n";
    }
    else if(userInput == "help-all") {
        if(blockchain_version != "1.0") {
            for(int c=0;c<commandDescriptions.size();c++)
                std::cout << commandDescriptions[c] << "\n";
        } else {
            for(int c=0;c<commandDescriptions.size()-9;c++)
                std::cout << commandDescriptions[c] << "\n";
        }
    }
    else if(userInput.length()>5 && userInput.substr(userInput.length()-5,
                                                     userInput.length()) == "-help") {
        bool commandExists;
        for(int c=0;c<commandDescriptions.size()-1;c++) {
            if(commandDescriptions[c].starts_with(userInput.substr(0,userInput.length()-5))) {
                std::cout << "\n" << commandDescriptions[c];
                commandExists = true;
                break;
            }
        }
        if(!commandExists) {
            std::cout << "command doesn\'t exist";
        }
    }
    else if(userInput == "create-wa") {
        std::cout << "\ncreating wallet address...\n";
        auto [fstNewAddrs,sndNewAddrs] = wallet_address.GenerateNewWalletAddress("dump aes256-key");
        std::cout << "wallet address created\nwallet address:\t";
        walletAddress = fstNewAddrs;
        std::cout << std::hex << to8_64_str(walletAddress);
        std::cout << std::endl << "save these values on your device\n";
        walletAddresses.push_back(walletAddress);
        walletMap.insert(itWalletMap, std::pair<std::shared_ptr<uint64_t>,
                         std::vector<std::shared_ptr<uint8_t>>>(walletAddress,
                                                                sndNewAddrs));
        std::cout << "wallet address saved on map\n";
    }
    else if(userInput == "buy" || userInput == "sell") {
        uint32_t amount;
        int32_t storedCrypto;
        std::string secondWalletAd;
        
        // ask for walletAddress of receiver or seller, key isn't requiried
        if(userInput == "buy") {
            secondWalletAd = "sender";
        } else { // sell
            secondWalletAd = "receiver";
        }
        if(walletMap.empty()) { // Don't use: else Use \"dump-wallet512\" and copy paste
            std::cout << "wallet map is empty, input your wallet address."
                      <<"If you don\'t have one, type \"nw \" here,press enter, "
                      << "if you have one, press enter, copy paste wallet address"
                      << "from where you saved it:\t";
            std::string noWallet;
            std::cin >> noWallet;
            std::string strWallet;
            if(noWallet == "yw") {
                std::cin >> strWallet;
                walletAddress = usrInWallet512(strWallet);
                // verify inputted wallet
                wallet_address.verifyInputWallet(walletAddresses, walletAddress);
                
                // if walletAddress valid, input wallet keys
                std::cout << "\ninput your aes256 wallet key 1 as hex:\t";
                std::string key1Str;
                std::cin >> key1Str;
                userAESmapkeys[0] = aesKeyToSPtr<uint8_t>(key1Str);
                std::cout << "\ninput your aes256 wallet key 2 as hex:\t";
                std::string key2Str;
                std::cin >> key2Str;
                userAESmapkeys[1] = aesKeyToSPtr<uint8_t>(key2Str);
                walletMap.insert(itWalletMap, std::pair<std::shared_ptr<uint64_t>,
                                 std::vector<std::shared_ptr<uint8_t>>>
                                 (walletAddress, userAESmapkeys));
                
            } else {// only difference is first trWallet parameter is nullptr
                storedCrypto=0;
                walletAddress = nullptr;
            }
        } else { // if walletMap not empty
            std::cout << "\nwallet address found\n";
        }
            std::cout << "\ninput" << secondWalletAd << "s wallet address:\t";
            std::string str_wallet;
            std::cin >> str_wallet;
            secondWallet = usrInWallet512(str_wallet);
            wallet_address.verifyInputWallet(walletAddresses, walletAddress);
            std::cout << "\nwallet data saved\n";
            struct Wallet trWallet{walletAddress, userAESmapkeys, walletMap};
            std::cout << "\ninput amount:\t";
            std::cin >> amount;
            struct userData user_data {walletMap,transactions,transactionhashesW,
                                       trnsLengths};
            storedCrypto = user_data.setBalance();
            auto [newWA,newKeys] = trWallet.new_transaction(secondWallet,walletAddress,
                                                        amount,mempool,
                                                        "buy", transactionhashesW,
                                                        transactions, 
                                                        storedCrypto,
                                                        "dump aes256-key");
            walletAddress = newWA;
            userAESmapkeys = newKeys;
    }
    else if(userInput == "e-wallet-aes128" || userInput == "e-wallet-aes192" ||
            userInput == "e-wallet-aes256") {
        std::string usrCommand;
        std::string ACmndNoKey;
        std::string ACmndWithKey; // alternative command with key
        std::shared_ptr<uint8_t> encWalletAesAlgKey;
        std::string algorithm;
        uint32_t keysize;
        usrCommand = userInput;
        std::string aesAlgKey;
        if(userInput == "e-wallet-aes128") {
            ACmndNoKey = "enc-aes128";
            ACmndWithKey = "enc-aes128-genkey";
            algorithm = "aes128";
            keysize = 16;
        }
        else if(userInput == "e-wallet-aes192") {
            ACmndNoKey = "enc-aes192";
            ACmndWithKey = "enc-aes192-genkey";
            algorithm = "aes192";
            keysize = 24;
        } else {
            ACmndNoKey = "enc-aes256";
            ACmndWithKey = "enc-aes256-genkey";
            algorithm = "aes256";
            keysize = 32;
        }
        
        if(walletMap.empty()) {
            std::cout << "no wallet saved, if you want to encrypt manually, try "
                      << "\"" << ACmndNoKey << "\" and input both input and key, if you"
                      << " want to use an automatically generated key, use"
                      << " \"" << ACmndWithKey << "\".";
        } else {
            std::cout << "\nwallet found\ninput " << algorithm << " key as hex"
                      << "(hex digits only):\t";
            std::cin >> aesAlgKey;
            encWalletAesAlgKey = aesKeyToSPtr<uint8_t>(aesAlgKey,keysize);
            std::cout << "\nis the key you inputted correct:\t";
            for(int c=0;c<16;c++) {
                std::cout << std::hex << (short)encWalletAesAlgKey.get()[c];
            }
            std::cout << std::endl;
            std::vector<std::shared_ptr<uint8_t>> walletKeys;
            for(const auto [wa,walletkeys] : walletMap) {
                walletAddress = wa;
                walletKeys = walletkeys;
            }
            if(algorithm == "aes128") {
                ciphertextW = aes128.encrypt(to8_64_str(walletAddress),
                                             encWalletAesAlgKey);
            ciphertextK1 = aes128.encrypt(aesKeyToStr<uint8_t>
                                          (walletKeys[0],16),
                                          encWalletAesAlgKey);
            ciphertextK2 = aes128.encrypt(aesKeyToStr<uint8_t>
                                          (walletKeys[1],16),
                                          encWalletAesAlgKey);
            }
            else if(algorithm == "aes192") {
                ciphertextW = aes192.encrypt(to8_64_str(walletAddress),
                                             encWalletAesAlgKey);
                ciphertextK1 = aes192.encrypt(aesKeyToStr<uint8_t>
                                              (walletKeys[0],24),
                                              encWalletAesAlgKey);
                ciphertextK2 = aes192.encrypt(aesKeyToStr<uint8_t>
                                              (walletKeys[1],24),
                                              encWalletAesAlgKey);
            } else {
                ciphertextW = aes256.encrypt(to8_64_str(walletAddress),
                                             encWalletAesAlgKey);
                ciphertextK1 = aes256.encrypt(aesKeyToStr<uint8_t>
                                              (walletKeys[0]),
                                              encWalletAesAlgKey); // keysize = 32
                ciphertextK2 = aes256.encrypt(aesKeyToStr<uint8_t>
                                              (walletKeys[1]),
                                              encWalletAesAlgKey); // keysize = 32
            }
            std::cout << "\nciphertext of wallet address:\t" << ciphertextW
                      << "\n\nwarning: an " << "encrypted wallet address is not"
                      << " usable until you decrypt it";
            walletAddress = nullptr;
            std::cout << "\n\nciphertext of key 1:\t" << ciphertextK1;
            std::cout << "\n\nciphertext of key 2:\t" << ciphertextK2;
            std::cout << "\n\nsave these values and keys as they won\'t be "
                      << "saved here and you won\'t be able to access your wallet again";
            std::cout << "\nunencrypted wallet data will be gone until you decrypt it,"
                      << " are you sure you want to continue\ntype \"y\" for yes, "
                      << "\"n\" for no";
            std::string confirm;
            bool terminate = false;
            while(terminate == false) {
                std::cin >> confirm;
                if(confirm == "n" or confirm == "no") {
                    std::cout << "\nprocess terminated, wallet not encrypted.";
                    // reset ciphertexts
                    ciphertextW = "";
                    ciphertextK1 = "";
                    ciphertextK2 = "";
                    terminate = true;
                }
                else if(confirm == "y" or confirm == "yes") {
                    std::cout << "\nclearing unencrypted wallet data...";
                    usedEncAlg = "aes128";
                    walletMap.clear();
                    std::cout << "\ndone";
                    terminate = true;
                } else {
                    std::cout << "invalid input\n(y) or (n)";
                }
            }
        }
    }
    // DEBUG
    // std::cout << commandDescriptions.size() << "\n\n" << listOfCommands.size();
    std::cout << "\n\nline 339, main.cpp:\t";
    /* TEST walletAddress */
    // std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> testMap;
    // std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>>::iterator
    // itMap = testMap.begin();
    // std::vector<std::shared_ptr<uint8_t>> senderAESmap;
    // std::vector<std::shared_ptr<uint8_t>> receiverAESmap;
    // std::vector<std::shared_ptr<uint8_t>> AESkeysTr;
    
    // transaction list in wallet
    // std::vector<std::shared_ptr<uint64_t>> transactionhashesW;
    
    // std::shared_ptr<uint64_t> senderWallet(new uint64_t[8]);
    // auto [fst,snd] = wallet_address.GenerateNewWalletAddress();
    // auto [fst1,snd1] = wallet_address.GenerateNewWalletAddress();
    // walletAddress = fst; // receiver
    // receiverAESmap = snd;
    // senderWallet = fst1;
    // senderAESmap = snd1;
    // walletAddresses.push_back(walletAddress);
    // walletAddresses.push_back(senderWallet);
    
    // encrypted transaction data for a single wallet.
    // std::map<std::string, std::shared_ptr<uint8_t>> transactionsEnc;
    // std::map<std::string, std::shared_ptr<uint8_t>>::iterator it = transactionsEnc.begin();
    
    /* only insert own wallet data to testMap, burning will be sending crypto 
     * to dead account. you have to make sure to have the correct wallet address
     * to send to
     */
    // testMap.insert(itMap, std::pair<std::shared_ptr<uint64_t>, 
    //               std::vector<std::shared_ptr<uint8_t>>>(walletAddress, receiverAESmap));
    // struct Wallet TestWallet{nullptr, snd, testMap};
    // auto [Fst,Snd] = TestWallet.new_transaction(senderWallet,walletAddress,/*amount*/ 50000,
    //                                             mempool,"buy", transactionhashesW,
    //                                             transactionsEnc, 
    //                                             /* storedCrypto */ 20000,
    //                                             "dump aes256-key");
    // walletAddress = Fst;
    // receiverAESmap = Snd;
    /* TEST walletAddress DONE */
    
    // if(blockMined == false) {
    //     std::vector<uint64_t> trnsLength;
    //     /* TEST PoW MINE */
    //     trnsLength.push_back(trns.length());
    //     trnsLength.push_back(trns1.length());
    //     trnsLength.push_back(trns2.length());
    //     trnsLength.push_back(trns3.length());
    //     trnsLength.push_back(trns4.length());
    //     trnsLength.push_back(trns.length());
    //     trnsLength.push_back(trns1.length());
    //     trnsLength.push_back(trns2.length());
    //     trnsLength.push_back(trns1.length());
    //     trnsLength.push_back(trns2.length());
    //     /* TEST PoW MINE */
    //     std::tuple<std::shared_ptr<uint64_t>,std::string,uint32_t,uint64_t, 
    //           double,std::shared_ptr<uint64_t>, double, double>
    //     unverified_block_data = block.data(mempool2);
    //     uint32_t blockchainSize;
    //     uint64_t nonce;
    //     std::shared_ptr<uint64_t> prevBlockHash(new uint64_t[8]);
    //     std::string timestamp;
    //     double difficulty, nextBlockGenTime, avHashrate;
    //     std::tie(prevBlockHash, timestamp, blockchainSize, nonce, difficulty,
    //              merkle_root,nextBlockGenTime, avHashrate) = unverified_block_data;
    //     auto [isblockmined,clean_mempool] = ProofofWork.mineBlock(transactionsEnc,
    //                                                               nonce, difficulty,
    //                                                               mempool,
    //                                                               merkle_root,
    //                                                               trnsLength);
    //     std::cout << "\nmempool cleaned";
    //     blockMined = isblockmined;
        
    //     if(blockMined) {
    //         std::cout << "\nblock mined successfully";
    //         std::cout << "\nrepresenting correct block in blockhain...\n\n";
    //         std::cout << block.data_str(prevBlockHash,timestamp,blockchainSize,
    //                                     nonce,difficulty,nextBlockGenTime,
    //                                     avHashrate,clean_mempool,blockchain_version);
    //         std::cout << "\n\nblock added to blockchain";
    //         /* wrong mempool cannot have less than correct mempool since wrong
    //          * mempool has new false transaction, if there is a modified 
    //          * transaction hash, it won't work, therefore needs further updates.
    //          * More functionality will be added in further versions
    //          */
    //          std::cout << "\n\nclean mempool: \n";
    //          for(int i=0;i<clean_mempool.size();i++) {
    //              for(int c=0;c<8;c++)
    //                 std::cout << std::hex << clean_mempool[i].get()[c];
    //             std::cout << std::endl;
    //          }
    //     }
    // }
    std::cout << "\nline 339, main.cpp complete";
    return 0;
}
