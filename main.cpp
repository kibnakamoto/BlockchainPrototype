/*
 * A Blockchain Prototype that mimics the functions of a blockchain.
 * Around 4500 lines of code
 * Copyright (C) 2022 Taha Canturk
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
// 4404 lines
/* Author: Taha Canturk
 *  Github: kibnakamoto
 *  Project: BlockchainPrototype
 *   Start Date: Feb 9, 2022
 *    Last Update: June 19
 *     Software Version: 1.0
 */

/* TODO:
 * convert all vector matrices into a set for uniuqe values:
 * walletAddresses, mempool,wallet keys, transactionhashesW, etc.
 * 77 uses of vector in three files: main.cpp(55), block.h(13), MerkleTree.h(9)
 *
 * TODO: make get a command on else if and put if argv[2] == "something" for
         other parts(parse command line input)
* TODO: convert command UI input process into its own function if its also 
         used the same way in terminal, this way

 * NOTE: while printing wallet address or aes keys or anything like it in 
        hex/dec format instead of a proper hex string, copy pasting input 
        won't work properly which can make it complicated to copy paste it 
        into the console/terminal/command line
 */

#include <iostream>

#if __cplusplus > 201703L // if C++ 20 or above
    
    #include <string>
    #include <random>
    #include <time.h>
    #include <tuple>
    #include <map>
    #include <set>
    
    #if defined(_WIN32) || defined(_WIN64)
        #include <windows.h>
        #define OS_WINDOWS 1
    #else
        #include <unistd.h>
    #endif
    
    #include "conditions.h" // global conditions across all files
    #include "bigint.h"
    #include "sha512.h"
    #include "merkletree.h"
    #include "aes.h"
    #include "block.h"
    #include "wallet.h"
    #include "ui.h"
    
    int main(int argc,char** argv)
    {
        WalletAddress wallet_address = WalletAddress();
        SHA512 hash = SHA512();
        Block block = Block();
        PoW ProofofWork = PoW();
        AES::AES128 aes128;
        AES::AES192 aes192;
        AES::AES256 aes256;
        
        // block related declarations
        std::shared_ptr<uint64_t> merkle_root(new uint64_t[8]); // declare Merkle Root
        std::shared_ptr<uint64_t> walletAddress(new uint64_t[8]);
        std::vector<std::shared_ptr<uint64_t>> mempool; // declare mempool
        std::vector<std::shared_ptr<uint64_t>> walletAddresses; // All wallet addresses
        std::string blockchain_version = "1.0";
        bool blockMined = false;
        std::set<std::string> blockchain; // all blocks in the blockchain
        std::vector<std::shared_ptr<uint64_t>> blockhashes; // all block hashes
        std::vector<std::shared_ptr<uint64_t>> &unsafe_mempool = mempool;
        std::map<std::string, std::shared_ptr<uint8_t>> transactions_enc;
        std::map<std::string, std::shared_ptr<uint8_t>>::iterator
        it_trns_enc = transactions_enc.begin();
        std::vector<uint32_t> all_trns_lengths;
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
        std::vector<std::string> commandDescriptions
        {"help: show basic commands with descriptions",
         " -help: for command description, put after another command",
         "help-all: show all commands with description",
         "show w: show warranty information about the licence",
         "show c: show copying information about the licence",
         "create-wa: generate new wallet address",
         "buy: buy an amount, must specify amount after typing buy",
         "send: send an amount to another wallet",
         "sell: same as send but send to non-existant wallet address",
         "e-wallet-aes128: encrypt wallet with aes256, do not provide wallet address here, provide key",
         "e-wallet-aes192: encrypt wallet with aes192, do not provide wallet address here, provide key",
         "e-wallet-aes256: encrypt wallet with aes256, do not provide wallet address here, provide key",
         "e-wallet-aes128-genkey: encrypt wallet with aes256, do not provide wallet" +
         std::string("address here, do not provide key, for command line, add space after aes128"),
         "e-wallet-aes192-genkey: encrypt wallet with aes192, do not provide wallet" +
         std::string(" address here, do not provide key, for command line, add space after aes192"),
         "e-wallet-aes256-genkey: encrypt wallet with aes256, do not provide wallet" +
         std::string(" address here, do not provide key, for command line, add space after aes256"),
         "decrypt-wallet: decrypt wallet using chosen encryption algorithm, provide key",
         "get p-w keys: request private wallet keys",
         
         // in future use timestamp for get p-trns-data
         "get p-trns-data: request single transaction data, provide transaction index in wallet",
         "del-wallet: delete your wallet address, make sure wallet is empty before" +
         std::string(" doing so, wallet components will be deleted and cannot be brought back"),
         "exit: will terminate and exit program",
         "quit: will terminate and exit program",
         "burn [amount]: burn an amount of crypto(send to dead wallet address), provide amount",
         "hash-sha512 [input]: hash input with sha512",
         "enc-aes128 -genkey [input,key]: encrypt input with aes128, key is generated for you",
         "enc-aes192 -genkey [input,key]: encrypt input with aes192, key is generated for you",
         "enc-aes256 -genkey [input,key]: encrypt input with aes256, key is generated for you",
         "enc-aes128 [input,key]: encrypt input with aes128, use own key in hex format",
         "enc-aes192 [input,key]: encrypt input with aes192, use own key in hex format",
         "enc-aes256 [input,key]: encrypt input with aes256, use own key in hex format",
         "dec-aes128 [input,key]: decrypt ciphertext with aes128, provide key",
         "dec-aes192 [input,key]: decrypt ciphertext with aes192, provide key",
         "dec-aes256 [input,key]: decrypt ciphertext with aes256, provide key",
         "get myahr: print my average hashrate",
         "get blockchain: prints all blocks in blockchain",
         "get block-hash [block index]: get block hash, provide index",
         "get block-nonce [block index]: get block nonce, provide index",
         "get block-timestamp [block index]: get block timestamp, provide index",
         "get block-merkle-r [block index]: get merkle root of block, provide index",
         "get block-difficulty [block index]: get difficulty of block, provide index",
         "get block-ahr [block index]: get average hash rate of block miners, provide index",
         "get nblocktime: get next block generation time",
         "get blockchain-size: print amounts of blocks in blockchain",
         "get version: get blockchain version",
         "get mempool: print verified mempool hashes in current block",
         "enc-algs: available encryption/decryption algorithms",
         "start mine: start mining",
         "dump-wallet512: dump 512-bit wallet address as hex", // after this is not in version 1
         "get tr-target: print transaction target",
         "get tr-hash: print transaction hash",
         "get tr-ciphertext [trns index]: print transaction ciphertext",
         "get tr-timestamp [trns index]: print transaction timestamp",
         "dump all-trnsData: dump all transaction data in wallet",
         "get blockchain-ahr: get average hashrate over all blockchain",
         "get block-target [block index]: get block target hash, provide index"};
        
        // wallet related declarations
        std::map<std::string,std::shared_ptr<uint8_t>> transactions;
        std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>> walletMap;
        std::map<std::shared_ptr<uint64_t>, std::vector<std::shared_ptr<uint8_t>>>::iterator
        itWalletMap = walletMap.begin();
        std::vector<std::shared_ptr<uint8_t>> userAESmapkeys;
        std::vector<std::shared_ptr<uint8_t>> AESkeysTr;
        std::vector<uint32_t> trnsLengths;
        std::string ciphertextW = ""; // wallet
        std::string ciphertextK1 = ""; // key1
        std::string ciphertextK2 = ""; // key2 
        std::string usedEncAlg = "";
        int32_t storedCrypto;
        
        // transaction list in wallet
        std::vector<std::shared_ptr<uint64_t>> transactionhashesW;
        
        // second wallet address
        std::shared_ptr<uint64_t> secondWallet(new uint64_t[8]);
        
        /* terminal UI */
        // licence disclaimer
        std::cout << "\nBlockchain Prototype Copyright (C) 2022 Taha Canturk\n"
                  << "This program comes with ABSOLUTELY NO WARRANTY; for details "
                  << "type \'show w\'. This is free software, and you are welcome "
                  << "to redistribute it under certain conditions; type \'show c\' "
                  << "for details.\n";
        
        std::cout << "\nfor basic command list, input \"help\"\n"
                  << "for all commands, input \"help-all\"\n";
        
        if(argc != 1 && !console_ui_activate) {
            if(argc == 2 && strcmp(argv[1], "help") == 0) {
                for(int c=0;c<18;c++) {
                    std::cout << commandDescriptions[c] << std::endl;
                }
            }
            else if(argc == 2 && strcmp(argv[1],"help-all") == 0) {
                if(blockchain_version != "1.0") {
                    for(int c=0;c<commandDescriptions.size();c++)
                        std::cout << commandDescriptions[c] << "\n";
                } else {
                    for(int c=0;c<commandDescriptions.size()-9;c++)
                        std::cout << commandDescriptions[c] << "\n";
                }
            }
            else if(argc >= 3 && strcmp(argv[argc-1],"-help") == 0) {
                bool commandExists = false;
                std::string tmp = "";
                int commandLength;
                for(int c=1;c<argc;c++) { // get char array input as string
                    tmp += argv[c];
                    if(c < argc-1) {
                        commandLength = tmp.length();
                    }
                    tmp += (c<argc-1) ? " " : "";
                }
                for(int c=0;c<commandDescriptions.size()-1;c++) {
                    if(commandDescriptions[c].starts_with(tmp.substr
                                                          (0,tmp.length()-6)) && 
                       commandDescriptions[c][tmp.length()-6] ==  ':') {
                        std::cout << "\n" << commandDescriptions[c];
                        commandExists = true;
                    }
                }
                if(!commandExists) {
                    std::cout << "command doesn\'t exist";
                }
            }
            else if(argc == 2 && strcmp(argv[1],"create-wa") == 0) {
                std::cout << "\ncreating wallet address...\n";
                auto [fstNewAddrs,
                      sndNewAddrs] = wallet_address
                                     .GenerateNewWalletAddress("dump aes256-key");
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
            else if(argc == 2 && (strcmp(argv[1], "buy") == 0 ||
                    strcmp(argv[1], "sell") == 0 || strcmp(argv[1], "send") == 0)) {
                uint32_t amount;
                std::string secondWalletAd;
                
                // ask for walletAddress of receiver or sender, key isn't requiried
                if(argv[1] == "buy") {
                    secondWalletAd = "sender";
                } else { // send or sell
                    secondWalletAd = "receiver";
                }
                if(walletMap.empty()) {
                    std::cout << "wallet map is empty, input your wallet address."
                              << " If you don\'t have one, type \"nw \" here,press enter, "
                              << "if you have one, press enter, copy paste wallet address"
                              << " from where you saved it:\t";
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
                std::cout << "\ninput " << secondWalletAd << "s wallet address:\t";
                std::string str_wallet;
                std::cin >> str_wallet;
                secondWallet = usrInWallet512(str_wallet);
                wallet_address.verifyInputWallet(walletAddresses, walletAddress);
                std::cout << "\nwallet data verified\n";
                struct Wallet trWallet{walletAddress, userAESmapkeys, walletMap};
                std::cout << "\ninput amount:\t";
                std::cin >> amount;
                
                struct userData user_data {walletMap,transactions,transactionhashesW,
                                           trnsLengths};
                storedCrypto = user_data.setBalance();
                
                /* since newTransaction doesn't have sell in sellorbuy and both
                 * perform the same task for now
                 */
                if(strcmp(argv[1],"sell") == 0) {
                    char tmp[4] = {'s','e','n','d'}; // send
                    argv[1] = tmp;
                }
                auto [newWA,newKeys] = trWallet.new_transaction(secondWallet,
                                                                walletAddress,
                                                                amount,mempool,
                                                                argv[1],
                                                                transactionhashesW,
                                                                transactions,
                                                                storedCrypto,
                                                                trnsLengths,
                                                                all_trns_lengths,
                                                                "dump aes256-key");
                
                // append transactions of single wallet to all transactions
                // ciphertexts in blockchain
                for(const auto [ciphertxt,trns_keys] : transactions) {
                    // add transaction ciphertext and keys if its not already in
                    // transactions_enc
                    if(transactions_enc.find(ciphertxt) == transactions_enc.end()) {
                        transactions_enc.insert(it_trns_enc,std::pair<std::string,
                                                std::shared_ptr<uint8_t>>(ciphertxt,
                                                                          trns_keys));
                    }
                }
                walletAddress = newWA;
                userAESmapkeys = newKeys;
            }
            else if((argc == 2 || argc == 3) && (strcmp(argv[1],"e-wallet-aes128") == 0 ||
                                                 strcmp(argv[1],"e-wallet-aes192") == 0 ||
                                                 strcmp(argv[1],"e-wallet-aes256") == 0)) {
                std::string ACmndNoKey;
                std::string algorithm;
                uint32_t keysize;
                std::string aesAlgKey;
                if(strcmp(argv[1], "e-wallet-aes128") == 0) {
                    ACmndNoKey = "enc-aes128";
                    algorithm = "aes128";
                    keysize = 16;
                }
                else if(strcmp(argv[1], "e-wallet-aes192") == 0) {
                    ACmndNoKey = "enc-aes192";
                    algorithm = "aes192";
                    keysize = 24;
                } else if(strcmp(argv[1], "e-wallet-aes256") == 0) {
                    ACmndNoKey = "enc-aes256";
                    algorithm = "aes256";
                    keysize = 32;
                }
                
                std::shared_ptr<uint8_t> encWalletAesAlgKey(new uint8_t[keysize]);
                if(walletMap.empty()) {
                    std::cout << "no wallet saved, if you want to encrypt manually, try "
                              << "\"" << ACmndNoKey << "\" and input both input and key, if you"
                              << " want to use an automatically generated key, put"
                              << " \"e-wallet-" << algorithm << " -genkey\".";
                } else {
                    if(argc == 2) { // if key generation not requested
                        std::cout << "\nwallet found\ninput " << algorithm << " key as hex"
                                  << "(hex digits only):\t";
                        std::cin >> aesAlgKey;
                        encWalletAesAlgKey = aesKeyToSPtr<uint8_t>(aesAlgKey,keysize);
                        std::cout << "\nis the key you inputted correct as hex integer:\t";
                        for(int c=0;c<keysize;c++) {
                            std::cout << std::hex << (short)encWalletAesAlgKey.get()[c];
                        }
                        std::cout << "\n\ninteger value will have a few missing zeros"
                                  << "which is fine but if a big part or everything is"
                                  << "wrong, that is a problem, please stop the process and "
                                  << "report the problem";
                        std::cout << std::endl;
                    }
                    else {
                        if(algorithm == "aes128") {
                            encWalletAesAlgKey = generateAES128Key();
                        }
                        else if(algorithm == "aes192") {
                            encWalletAesAlgKey = generateAES192Key();
                        }
                        else { // aes256
                            encWalletAesAlgKey = generateAES256Key();
                        }
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
                        } else { // aes256
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
                                  << "saved here and you won\'t be able to access";
                        std::cout << " your wallet again\nunencrypted wallet "
                                  << "data will be gone until you decrypt it, "
                                  << "are you sure you want to continue\ntype "
                                  << "\"y\" for yes, \"n\" for no: ";
                        std::string confirm;
                        bool terminate = false;
                        while(!terminate) {
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
                                usedEncAlg = algorithm;
                                walletMap.clear();
                                std::cout << "\ncomplete\nencryption key:\t" << std::hex
                                          << aesKeyToStr<uint8_t>(encWalletAesAlgKey,keysize);
                                terminate = true;
                            } else {
                                std::cout << "invalid input\n(y) or (n)";
                            }
                        }
                    }
                }
            }
            else if(argc == 2 && strcmp(argv[1],"decrypt-wallet") == 0) {
                uint32_t keysize;
                std::string aesKeyStr;
                if(usedEncAlg == "aes128") {
                    keysize = 16;
                }
                else if(usedEncAlg == "aes192") {
                    keysize = 24;
                }
                else if(usedEncAlg == "aes256") {
                    keysize = 32;
                }
                std::shared_ptr<uint8_t> edkey(new uint8_t[keysize]);
                std::string decStrWalletaddress;
                std::string decStrWalletk1;
                std::string decStrWalletk2;
                std::shared_ptr<uint8_t> decWalletk1(new uint8_t[keysize]);
                std::shared_ptr<uint8_t> decWalletk2(new uint8_t[keysize]);
                if(walletMap.empty() && ciphertextW != "") {
                    std::cout << "ciphertext of wallet address found and no unencrypted data."
                              << "Decrypting a wallet address using the " << usedEncAlg
                              << ".\nciphertext of wallet address:\t" << ciphertextW
                              << "\n\nciphertext of first " << usedEncAlg << " key:\t"
                              << ciphertextK1 << "\n\nciphertext of second " << usedEncAlg
                              << " key:\t" << ciphertextK2 << "\n\ninput " << keysize
                              << " byte " << usedEncAlg << " key:\t";
                    std::cin >> aesKeyStr;
                    edkey = aesKeyToSPtr<uint8_t>(aesKeyStr,keysize);
                    std::cout << "\ndecrypting wallet data...\n";
                    if(usedEncAlg == "aes128") {
                        decStrWalletaddress = aes128.decrypt(ciphertextW,edkey);
                        decStrWalletk1 = aes128.decrypt(ciphertextK1,edkey);
                        decStrWalletk2 = aes128.decrypt(ciphertextK2,edkey);
                    }
                    else if(usedEncAlg == "aes192") {
                        decStrWalletaddress = aes192.decrypt(ciphertextW,edkey);
                        decStrWalletk1 = aes192.decrypt(ciphertextK1,edkey);
                        decStrWalletk2 = aes192.decrypt(ciphertextK2,edkey);
                    }
                    else if(usedEncAlg == "aes256") {
                        decStrWalletaddress = aes256.decrypt(ciphertextW, edkey);
                        decStrWalletk1 = aes256.decrypt(ciphertextK1,edkey);
                        decStrWalletk2 = aes256.decrypt(ciphertextK2,edkey);
                    }
                    /* delete padding caused by aes encryption, since all keys and
                     * wallet address length is 512-bits as string which is a multiple
                     * of aes block(16 bytes), its not necesarry to delete padding
                     *  but is a good precation to take just in case
                     */
                    uint32_t keySizeBits = keysize<<3;
                    decStrWalletaddress.erase(512,512-decStrWalletaddress.length());
                    decStrWalletk1.erase(keySizeBits,keySizeBits-decStrWalletk1.length());
                    decStrWalletk2.erase(keySizeBits,keySizeBits-decStrWalletk2.length());
                    walletAddress = usrInWallet512(decStrWalletaddress);
                    decWalletk1 = aesKeyToSPtr<uint8_t>(decStrWalletk1,keysize);
                    decWalletk2 = aesKeyToSPtr<uint8_t>(decStrWalletk2,keysize);
                    std::cout << "wallet components decrypted. Wallet address as plaintext:\t"
                              << decStrWalletaddress << "\ndecrypted first " << usedEncAlg
                              << " key as plaintext:\t" << decStrWalletk1 
                              << "\ndecrypted second " << usedEncAlg
                              << " key as plaintext:\t" << decStrWalletk2
                              << "\n\nif these values are wrong, please report this "
                              <<  "problem at https://github.com/kibnakamoto/"
                              << "BlockchainPrototype/issues or email the issue at"
                              << " kibnakanoto@protonmail.com";
                    std::vector<std::shared_ptr<uint8_t>> walletKeysDec;
                    walletKeysDec.push_back(decWalletk1);
                    walletKeysDec.push_back(decWalletk2);
                    walletMap.insert(itWalletMap,std::pair<std::shared_ptr<uint64_t>,
                                     std::vector<std::shared_ptr<uint8_t>>>
                                     (walletAddress,walletKeysDec));
                    std::cout << "\nwallet data saved\n";
                } else {
                    std::cout << "\nNO ENCRYPTED WALLET FOUND\n";
                    exit(EXIT_FAILURE);
                }
            }
            else if(argc == 4 || argc == 3 && strcmp(argv[1],"get") == 0) {
                if(strcmp(argv[2],"p-w") == 0 && strcmp(argv[3],"keys") == 0) {
                   std::cout << "\nsearching wallet for keys...\n";
                if(walletMap.empty()) {
                    std::cout << "error: no wallet found";
                    exit(EXIT_FAILURE);
                }
                for(const auto [walletAd,walletKeys] : walletMap) {
                    std::cout << "key 1:\t";
                    for(int c=0;c<32;c++) std::cout << std::hex
                                                    << (short)walletKeys[0].get()[c];
                    
                    std::cout << std::endl << std::endl << "key 2:\t";
                    for(int c=0;c<32;c++) std::cout << std::hex
                                                    << (short)walletKeys[1].get()[c];
                }
                std::cout << "\n\nif you want to also see your wallet address, type \""
                          << "get wa\"";
                }
                else if(argc == 3 && strcmp(argv[2],"p-trns-data") == 0) {
                    if(transactionhashesW.empty()) {
                        std::cout << "\nzero transactions in wallet\n";
                        exit(EXIT_FAILURE);
                    }
                    if(walletMap.empty()) {
                        std::cout << "\nno wallet found\n";
                        exit(EXIT_FAILURE);
                    }
                    std::cout << "\nthere are " << transactionhashesW.size()
                              << " transactions in your wallet\nstate index of transaction"
                              << " (index starts from zero), if you want all transaction "
                              << "data or you don\'t know the index, type\"get"
                              << " all-trns-data\":\t";
                    uint64_t index;
                    std::cin >> index;
                    std::cout << "\ntransaction hash:\t";
                    for(int c=0;c<8;c++) std::cout << std::hex
                                                   << transactionhashesW[index]
                                                      .get()[c];
                    std::string plaintext;
                    uint64_t trnsIndex;
                    std::string ciphertextTr;
                    std::shared_ptr<uint8_t> trnsKey;
                    std::string correctPlaintext;
                    std::vector<bool> trns_bool_vector;
                    
                    // find ciphertext and key index of transaction encryption map
                    for(const auto [cph,ckey] : transactions) {
                        /* delete padding caused by encryption
                           check which length creates correct hash to find index using 
                           single wallet mempool */
                        plaintext = aes256.decrypt(cph,ckey);
                        for(uint64_t c=0;c<trnsLengths.size();c++) {
                            plaintext.erase(trnsLengths[c],plaintext.length()-
                                            trnsLengths[c]);
                            std::shared_ptr<uint64_t> hash = sha512(plaintext);
                            for(uint64_t i=0;i<transactionhashesW.size();i++) {
                                for(int j=0;j<8;j++) {
                                    if(transactionhashesW[i].get()[j] == 
                                       hash.get()[j]) {
                                        trns_bool_vector.push_back(true);
                                        trnsIndex = c;
                                        ciphertextTr = cph;
                                        trnsKey = ckey;
                                        correctPlaintext = plaintext;
                                        goto stop;
                                    }
                                }
                            }
                        }
                    }
                    stop:
                        if(std::find(trns_bool_vector.begin(),
                           trns_bool_vector.end(), false) != trns_bool_vector.end()) {
                            std::cout << "\nerror: transaction decryption failed."
                                      << "\nreason: unknown, dump encrypted transaction keys?";
                            std::string dumpOrNo;
                            std::cin >> dumpOrNo;
                            if(dumpOrNo == "yes" || "y") {
                                for(const auto [cph,ckey] : transactions) {
                                    std::cout << "\nciphertext:\t" << cph
                                              << "\naes256 key:\t"
                                              << aesKeyToStr<uint8_t>(ckey);
                                }
                            }
                        } else {
                            std::cout << "\ndecrypted transaction data\nplaintext:\t"
                                      << correctPlaintext << "\ntrns index:\t"
                                      << trnsIndex << "\nciphertext:\t"
                                      << ciphertextTr << "\naes256 transaction key:\t"
                                      << trnsKey;
                        }
                }
                else if(argc == 3 && strcmp(argv[2],"myahr") == 0) {
                    uint32_t accuracy;
                    std::cout << "input accuracy of hashrate (how many seconds should"
                              << " the calculation last?)\ninput in decimal format"
                              << "(no floating points):\t";
                    std::cin >> accuracy;
                    std::cout << "\ncalculating average hashrate...";
                    uint64_t hashrate = Blockchain::calcHashRateSha512(accuracy);
                    std::cout << "\nyour hashrate:\t" << std::dec << hashrate;
                }
                else if(argc == 3 && strcmp(argv[2],"blockchain") == 0) {
                    std::cout << "printing all blocks in the blockchain...";
                    if(blockchain.empty()) {
                        std::cout << "\nno blocks in blockchain, type "
                                  << "\"start mine\" to start mining";
                    } else {
                        std::cout << "blockchain:\t";
                        for (auto it = blockchain.begin(); it !=
                             blockchain.end(); ++it) {
                            std::cout << *it << std::endl << std::endl;
                        }
                    }
                }
                else if(strcmp(argv[2],"block-hash") == 0) {
                    uint64_t block_index = ui::check_index_block(argv,argc);
                    
                    if(blockhashes.empty()) {
                        std::cout << "\nno blockhashes found";
                    } else {
                        if(blockhashes.size() < block_index) {
                            std::cout << "\nindex bigger than blockchain size"
                                      << " (index starts from zero)";
                        } else {
                            std::cout << "\nblock hash:\t"
                                      << to8_64_str(blockhashes[block_index])
                                      << std::endl;
                        }
                    }
                }
                else if(strcmp(argv[2],"block-nonce") == 0) {
                    uint64_t index = ui::check_index_block(argv,argc);
                    if(blockchain.size() == 0 && index >= blockchain.size()) {
                        std::cout << "blockchain size smaller than " << index
                                  << ".\n";
                    } else {
                        std::cout << "\nfinding block nonce...\n";
                        std::set<std::string>::iterator itBlock = blockchain.begin();
                        std::string block = *std::next(blockchain.begin(), index);
                        std::string str_nonce = block.substr(block.find("nonce: "),
                                                             block.find("\ndifficulty"));
                        std::cout << "nonce:\t" << str_nonce;
                    }
                }
                else if(strcmp(argv[2],"block-timestamp") == 0) {
                    uint64_t index = ui::check_index_block(argv,argc);
                    if(!blockchain.empty()) {
                        std::cout << "\nfinding block timestamp...\n";
                        std::set<std::string>::iterator itBlock = blockchain.begin();
                        std::string block = *std::next(blockchain.begin(), index);
                        std::string str_time = block.substr(block.find("timestamp: "),
                                                             block.find("\nblockchain size"));
                        std::cout << "timestamp:\t" << str_time;
                    } else {
                        std::cout << "\nblockchain empty\n";
                    }
                }
                else if(strcmp(argv[2],"block-merkle-r") == 0) {
                    uint64_t index = ui::check_index_block(argv,argc);
                    std::string str_merkle_root;
                    if(!blockchain.empty()) {
                        std::cout << "\nfinding block merkle root...\n";
                        std::set<std::string>::iterator itBlock = blockchain.begin();
                        std::string block = *std::next(blockchain.begin(), index);
                        str_merkle_root = block.substr(block.find("merkle_root: "),
                                                       block.find("\napproximate time until next block"));
                        std::cout << "merkle_root:\t" << str_merkle_root;
                    } else {
                        std::cout << "\nblockchain empty\n";
                    }
                }
                else if(strcmp(argv[2],"block-difficulty") == 0) {
                    uint64_t index = ui::check_index_block(argv,argc);
                    std::string str_difficulty;
                    
                    if(!blockchain.empty()) {
                        std::cout << "\nfinding block difficulty...\n";
                        std::set<std::string>::iterator itBlock = blockchain.begin();
                        std::string block = *std::next(blockchain.begin(), index);
                        str_difficulty = block.substr(block.find("difficulty: "),
                                                       block.find("\nmerkle_root"));
                        std::cout << "difficulty:\t" << str_difficulty;
                    } else {
                        std::cout << "\nblockchain empty\n";
                    }
                }
                else if(strcmp(argv[2],"block-ahr") == 0) {
                    uint64_t index = ui::check_index_block(argv,argc);
                    std::string hashrate_str;
                    if(!blockchain.empty()) {
                        std::cout << "\nfinding block hashrate...\n";
                        std::set<std::string>::iterator itBlock = blockchain.begin();
                        std::string block = *std::next(blockchain.begin(), index);
                        hashrate_str = block.substr(block.find("Average hashrate of miners: "),
                                                       block.find("\nblockchain version"));
                        std::cout << "hashrate:\t" << hashrate_str;
                    } else {
                        std::cout << "\nblockchain empty\n";
                    }
                }
                else if(strcmp(argv[2],"nblocktime") == 0) {
                    uint64_t index = ui::check_index_block(argv,argc);
                    std::string nblocktime_str;
                    if(!blockchain.empty()) {
                        std::cout << "\nfinding next block generation time...\n";
                        std::set<std::string>::iterator itBlock = blockchain.begin();
                        std::string block = *std::next(blockchain.begin(), index);
                        nblocktime_str = block.substr(block.find("approximate time until next block: "),
                                                       block.find("\nAverage hashrate of miners"));
                        std::cout << "next block gen time:\t" << nblocktime_str;
                    } else {
                        std::cout << "\nblockchain empty\n";
                    }
                }
                else if(strcmp(argv[2],"blockchain-size") == 0) {
                    std::cout << "blockchain size:\t" << blockchain.size();
                }
                else if(strcmp(argv[2],"version") == 0) {
                    std::cout << "version of blockchain core:\t" << blockchain_version;
                }
                else if(strcmp(argv[2],"mempool") == 0) {
                    std::cout << "mempool size:\t" << mempool.size() << std::endl;
                    if(mempool.size() == 0) {
                        std::cout << "\nmempool empty";
                    } else {
                        std::cout << "\ndumping mempool...\n";
                        
                        // delay print for user to see mempool size
                        #ifdef OS_WINDOWS
                            Sleep(3000); // windows sleep function
                        #else
                            usleep(3000000); // unix sleep function
                        #endif
                    }
                    for(int i=0;i<mempool.size();i++)
                        std::cout << std::endl << to8_64_str(mempool[i]);
                }
                else if(strcmp(argv[2], "enc-algs") == 0) {
                    std::cout << "available encryption algorithms are aes128, "
                              << "aes192, aes256(recommended).";
                }
            } /* argv[1] = "get" */
            else if(argc == 2 && strcmp(argv[1],"del-wallet") == 0) {
                if(walletMap.empty()) {
                    std::cout << "\nno wallet found";
                    exit(EXIT_FAILURE);
                }
                std::shared_ptr<uint64_t> unverifiedWalletAddress(new uint64_t[8]);
                std::shared_ptr<uint8_t> unverifiedWalletk2(new uint8_t[8]);
                std::shared_ptr<uint8_t> unverifiedWalletk1(new uint8_t[8]);
                std::map<std::shared_ptr<uint64_t>,std::vector<std::shared_ptr<uint8_t>>>
                unverifiedWalletMap;
                std::map<std::shared_ptr<uint64_t>,std::vector<std::shared_ptr<uint8_t>>>::
                iterator ItUWMMap = unverifiedWalletMap.begin();
                std::string str_wallet_ad;
                std::string unverifiedStrWalletk1;
                std::string unverifiedStrWalletk2;
                
                std::cout << "verify user by inputting both wallet keys and walletAddress"
                          << "\ninput walletAddress:\t";
                std::cin >> str_wallet_ad;
                unverifiedWalletAddress = usrInWallet512(str_wallet_ad);
                std::cout << "\n\ninput first key of wallet:\t";
                std::cin >> unverifiedStrWalletk1;
                unverifiedWalletk1 = aesKeyToSPtr<uint8_t>(unverifiedStrWalletk1);
                std::cout << "\n\ninput second key of wallet:\t";
                std::cin >> unverifiedStrWalletk2;
                unverifiedWalletk2 = aesKeyToSPtr<uint8_t>(unverifiedStrWalletk2);
                std::vector<std::shared_ptr<uint8_t>> unverifiedWalletVec;
                unverifiedWalletVec.push_back(unverifiedWalletk1);
                unverifiedWalletVec.push_back(unverifiedWalletk2);
                unverifiedWalletMap.insert(ItUWMMap,std::pair<std::shared_ptr<uint64_t>,
                                           std::vector<std::shared_ptr<uint8_t>>>
                                           (unverifiedWalletAddress,unverifiedWalletVec));
                
                // verify inputted wallet data
                struct Wallet unv_wallet{unverifiedWalletAddress,unverifiedWalletVec,
                                         unverifiedWalletMap};
                wallet_address.verifyInputWallet(walletAddresses,unverifiedWalletAddress);
                unv_wallet.verifyOwnerData();
                
                // delete wallet
                std::string confirm;
                if(storedCrypto != 0) {
                    std::cout << "\n\nare you sure you want to delete wallet? Your balance is "
                              << storedCrypto << ". You cannot recover your balance after"
                              << "deletion\ntype d or delete for delete, any key for"
                              << "terminating process:\t";
                } else {
                std::cout << "\n\nAre you sure you want to delete wallet?\nYour balance"
                          << " is 0.\ntype \"d\" or \"delete\" for delete, "
                          << "type anything for terminating process:\t";
                }
                std::cin >> confirm;
                if(confirm == "d" || confirm == "delete") {
                    std::cout << "\ndeleting wallet...\n";
                    for(int c=0;c<8;c++)
                    walletMap.clear();
                    transactions.clear();
                    trnsLengths.clear();
                    userAESmapkeys.clear();
                    AESkeysTr.clear();
                    std::string ciphertextW = "";
                    std::string ciphertextK1 = "";
                    std::string ciphertextK2 = "";
                    std::string usedEncAlg = "";
                    
                    // delete wallet address from walletAddresses
                    for(int i=0;i<walletAddresses.size();i++) {
                        for(int c=0;c<8;c++) {
                            if(walletAddresses[i].get()[c] == walletAddress.get()[c]) {
                                walletAddresses.erase(walletAddresses.begin()+i);
                                goto stop_find;
                            }
                        }
                    }
                    stop_find:
                        walletAddress.reset();
                        std::cout << "wallet deleted";
                } else {
                    std::cout << "\nprocess terminated";
                    exit(EXIT_FAILURE);
                }
            }
            else if(argc == 2 && (strcmp(argv[1],"exit") == 0 || strcmp(argv[1],
                                                                   "quit") == 0)) {
                std::cout << "\nprogram terminated";
                exit(EXIT_FAILURE);
            }
            else if(argc == 2 && strcmp(argv[1],"burn") == 0) {
                if(!walletMap.empty()) {
                    std::string strWalletKey1;
                    std::shared_ptr<uint8_t> walletKey1(new uint8_t[32]);
                    std::string strWalletKey2;
                    std::shared_ptr<uint8_t> walletKey2(new uint8_t[32]);
                    std::vector<std::shared_ptr<uint8_t>> walletKeysVec;
                    std::map<std::shared_ptr<uint64_t>,std::vector<std::shared_ptr
                             <uint8_t>>> unv_wallet_map;
                    std::map<std::shared_ptr<uint64_t>,std::vector<std::shared_ptr
                             <uint8_t>>>::iterator unv_it_map = unv_wallet_map.begin();
                    
                    std::cout << "\nverify wallet data to burn crypto\ninput wallet key 1:\t";
                    std::cin >> strWalletKey1;
                    walletKey1 = aesKeyToSPtr<uint8_t>(strWalletKey1);
                    std::cout << "input wallet key 2:\t";
                    std::cin >> strWalletKey2;
                    walletKey2 = aesKeyToSPtr<uint8_t>(strWalletKey2);
                    
                    // append wallet keys to walletKeysVec for verification process
                    walletKeysVec.push_back(walletKey1);
                    walletKeysVec.push_back(walletKey2);
                    
                    // verify wallet
                    for(const auto [wa,walletKeys] : walletMap) {
                        unv_wallet_map.insert(unv_it_map,std::pair<std::shared_ptr
                                              <uint64_t>,std::vector<std::shared_ptr
                                              <uint8_t>>>(wa,walletKeysVec));
                        struct Wallet unv_wallet{wa,walletKeysVec,unv_wallet_map};
                        unv_wallet.verifyOwnerData();
                        wallet_address.verifyInputWallet(walletAddresses,wa);
                        walletAddress = wa;
                    }
                    
                    // create fake wallet address
                    auto [fakeWalletAd,fakeKeys] = wallet_address.GenerateNewWalletAddress();
                    bool walletAValid = wallet_address.verifyInputWallet(walletAddresses,
                                                                         fakeWalletAd);
                    
                    // if fake wallet address exists, create new wallet address
                    while(walletAValid) {
                        auto [newFakeWalletAd,newFakeKeys] = wallet_address.
                                                             GenerateNewWalletAddress();
                        fakeWalletAd = newFakeWalletAd;
                        wallet_address.verifyInputWallet(walletAddresses,
                                                         fakeWalletAd);
                    }
                    
                    // burn
                    uint32_t amountBurn;
                    std::cout << "\ninput amount to burn:\t";
                    std::cin >> amountBurn;
                    
                    // get accont balance
                    struct userData user_data {walletMap,transactions,
                                               transactionhashesW,trnsLengths};
                    storedCrypto = user_data.setBalance();
                    
                    // unv_wallet_map is now verified
                    struct Wallet trWallet {walletAddress,walletKeysVec,
                                            unv_wallet_map};
                    
                    // create transaction
                    auto [newWA,newKeys] = trWallet.new_transaction(fakeWalletAd,
                                                                    walletAddress,
                                                                    amountBurn,mempool,
                                                                    "sell",
                                                                    transactionhashesW,
                                                                    transactions,
                                                                    storedCrypto,
                                                                    trnsLengths,
                                                                    all_trns_lengths);
                    // append transactions of single wallet to all transactions
                    // ciphertexts in blockchain
                    for(const auto [ciphertxt,trns_keys] : transactions) {
                        // add transaction ciphertext and keys if its not already in
                        // transactions_enc
                        if(transactions_enc.find(ciphertxt) == transactions_enc.end()) {
                            transactions_enc.insert(it_trns_enc,std::pair<std::string,
                                                    std::shared_ptr<uint8_t>>(ciphertxt,
                                                                              trns_keys));
                        }
                    }
                    
                    // delete fake wallet address
                    fakeWalletAd.reset();
                }
                else {
                    std::cout << "\nno wallet address found";
                    exit(EXIT_FAILURE);
                }
            }
            else if((argc == 2 || argc == 3) && (strcmp(argv[1],"enc-aes128") == 0 ||
                    strcmp(argv[1],"enc-aes192") == 0 || strcmp(argv[1],"enc-aes256") == 0 || 
                    strcmp(argv[1],"dec-aes128") == 0 || strcmp(argv[1],"dec-aes192") == 0 ||
                    strcmp(argv[1],"dec-aes256") == 0)) {
                // find which algorithm algorithm
                unsigned short algorithmSize;
                bool withKey;
                std::string key_size_str = "";
                std::string plaintext;
                std::string ciphertext;
                std::string encOrDec = "";
                std::stringstream ss;
                for(int c=0;c<3;c++) { // encryption or decryption
                    encOrDec += argv[1][c];
                }
                
                // find algorithm size in bits
                for(int c=7;c<=9;c++) {
                    key_size_str += argv[1][c];
                }
                ss << key_size_str;
                ss >> algorithmSize;
                
                if(encOrDec == "enc") {
                    if(strcmp(argv[2],"-genkey") == 0) {
                        withKey = true;
                    } else {
                        withKey = false;
                    }
                    std::shared_ptr<uint8_t> aesKeyEnc(new uint8_t[algorithmSize/8]);
                    
                    std::cout << "\nencrypting input using aes" << algorithmSize
                              << ". input what to encrypt:\t";
                    std::cin >> plaintext;
                    if(!withKey) { // if key generation not requested
                        std::string aesKeyEncStr;
                        std::cout << "\ninput 32 byte aes" << algorithmSize
                                  << " key as hex:\t";
                        std::cin >> aesKeyEncStr;
                        aesKeyEnc = aesKeyToSPtr<uint8_t>(aesKeyEncStr,algorithmSize/8);
                        if(algorithmSize == 128) {
                            ciphertext = aes128.encrypt(plaintext,aesKeyEnc);
                        }
                        else if (algorithmSize == 192) {
                            ciphertext = aes192.encrypt(plaintext,aesKeyEnc);
                        }
                        else { // 256
                            ciphertext = aes256.encrypt(plaintext,aesKeyEnc);
                        }
                    } else {
                        if(algorithmSize == 128) {
                            aesKeyEnc = generateAES128Key();
                            ciphertext = aes128.encrypt(plaintext,aesKeyEnc);
                        }
                        else if(algorithmSize == 192) {
                            aesKeyEnc = generateAES192Key();
                            ciphertext = aes192.encrypt(plaintext,aesKeyEnc);
                        }
                        else { // 256
                            aesKeyEnc = generateAES256Key();
                            ciphertext = aes256.encrypt(plaintext,aesKeyEnc);
                        }
                    }
                    
                    std::cout << "ciphertext:\t" << ciphertext << "\n\naes"
                              << algorithmSize << " key:\t";
                    std::string aesKeyEncStr = aesKeyToStr<uint8_t>(aesKeyEnc,
                                                                    algorithmSize/8);
                    std::cout << aesKeyEncStr;
                } else {
                    std::string aesKeyDecStr;
                    std::shared_ptr<uint8_t> aesKeyDec(new uint8_t[algorithmSize/8]);
                    std::cout << "\nnote: if plaintext of the encrypted text is "
                              << "not a multiple of 16, there will be padding with"
                              << " zeros at the end of the decrypted ciphertext"
                              << " because aes algorithms encrypt plaintext as"
                              << " blocks of 16 bytes, if you know the length of"
                              << " plaintext, delete the padding of \"0\"\'s"
                              << "\n\ninput ciphertext:\t";
                    std::cin >> ciphertext;
                    std::cout << "\n\ninput aes" << algorithmSize << " key:\t";
                    std::cin >> aesKeyDecStr;
                    aesKeyDec = aesKeyToSPtr<uint8_t>(aesKeyDecStr,algorithmSize/8);
                    
                    if(algorithmSize == 128) {
                        plaintext = aes128.decrypt(ciphertext,aesKeyDec);
                    }
                    else if (algorithmSize == 192) {
                        plaintext = aes192.decrypt(ciphertext,aesKeyDec);
                    }
                    else { // 256
                        plaintext = aes256.decrypt(ciphertext,aesKeyDec);
                    }
                    std::cout << "\n\nplaintext:\t" << plaintext;
                }
            }
            else if(argc == 3 && strcmp(argv[1],"start") == 0 &&
                    strcmp(argv[2],"mine") == 0) {
                std::cout << "starting mining\n";
                if(!blockMined) {
                    std::tuple<std::shared_ptr<uint64_t>,std::string,uint32_t,uint64_t, 
                          double,std::shared_ptr<uint64_t>, double, double>
                    unverified_block_data = block.data(unsafe_mempool);
                    uint32_t blockchainSize;
                    uint64_t nonce;
                    std::shared_ptr<uint64_t> prevBlockHash(new uint64_t[8]);
                    std::string timestamp;
                    double difficulty, nextBlockGenTime, avHashrate;
                    std::tie(prevBlockHash, timestamp, blockchainSize, nonce, difficulty,
                             merkle_root,nextBlockGenTime, avHashrate) = unverified_block_data;
                    auto [isblockmined,clean_mempool] = ProofofWork.mineBlock(transactions_enc,
                                                                              nonce, difficulty,
                                                                              mempool,
                                                                              merkle_root,
                                                                              all_trns_lengths);
                    std::cout << "\nmempool cleaned";
                    blockMined = isblockmined;
                    
                    if(blockMined) {
                        std::cout << "\nblock mined successfully";
                        std::cout << "\nrepresenting correct block in blockhain...\n\n";
                        std::string current_block = block.data_str(prevBlockHash,
                                                                   timestamp,
                                                                   blockchainSize,
                                                                   nonce,difficulty,
                                                                   nextBlockGenTime,
                                                                   avHashrate,
                                                                   clean_mempool,
                                                                   blockchain_version);
                        std::cout << current_block;
                        blockchain.insert(current_block);
                        std::cout << "\n\nblock added to blockchain";
                        /* wrong mempool cannot have less than correct mempool since wrong
                         * mempool has new false transaction, if there is a modified 
                         * transaction hash, it won't work, therefore needs further updates.
                         * More functionality will be added in further versions
                         */
                        std::cout << "\n\nclean mempool: \n";
                        for(int i=0;i<clean_mempool.size();i++) {
                            for(int c=0;c<8;c++)
                                std::cout << std::hex << clean_mempool[i].get()[c];
                            std::cout << std::endl;
                        }
                            mempool = clean_mempool;
                            if(!walletMap.empty()) {
                                storedCrypto+=100;
                                std::cout << "added 100 to your balance. You know own "
                                          << storedCrypto << ".";
                            } else {
                                std::cout << "wallet map empty, cannot add";
                            }
                    }
                }
            }
            else if(argc == 3 && strcmp(argv[1],"show") == 0) {
                // if warranty info requested
                if(argv[2][0] == 'w') {
                    ui::show_w_command();
                }
                // if copying info requested
                else if(argv[2][0] =='c') {
                    ui::show_c_command();
                } else {
                    std::cout << "\ncommand not found, options are \"w\" and \"c\"";
                }
            }
            else {
                std::cout << "\ncommand not found\n";
            }
        }
        
        // console user interface
        ui::consoleUI(argc, commandDescriptions, blockchain_version,
                                 walletAddress, walletAddresses, walletMap,
                                 userAESmapkeys, storedCrypto, secondWallet,
                                 transactionhashesW, trnsLengths, mempool, ciphertextW,
                                 ciphertextK1, ciphertextK2, usedEncAlg,transactions,
                                 AESkeysTr,blockchain,all_trns_lengths,transactions_enc,
                                 blockhashes, blockMined, unsafe_mempool, merkle_root);
        
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
        std::cout << "\nline 1039: exitted normally";
        return 0;
    }
#else
    int main()
    {
        std::cout << "error: C++ version has to be C++20 or above";
        return 1;
    }
#endif
