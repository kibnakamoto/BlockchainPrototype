#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"

namespace MerkleTree
{
        std::vector<uint64_t*> merkleRoots;
        
        void MerkleRoot(std::vector<uint64_t*> mempool, uint64_t* merkle_root)
        {
            IntTypes int_type = IntTypes();
            SHA512 hash = SHA512();
            uint64_t len = mempool.size();
            uint64_t currlen = len;
            bool odd = true;
            if(len%2 == odd) { // make sure len is not odd
                uint64_t* oddZfill = new uint64_t[8];
                oddZfill = sha512("00000000");
                mempool.push_back(oddZfill);
                len++;
            }
            // uint64_t divCurrlen = len;
            bool divs;
            __uint128_t validlen = 2;
            // while (divCurrlen != 0) {
            //     divCurrlen /= 2;
            //     divs = (divCurrlen) % 2 == 0;
            //     if(divs != true) {
            //         // divCurrlen++;
            //     }
            while(validlen <= len) {
                validlen*=2;
            }
            
            while(len<validlen) { // append it 2, 4, 8... times
                uint64_t* oddZfill = new uint64_t[8];
                oddZfill = sha512("00000000");
                mempool.push_back(oddZfill);
                len++; // update len
            }
                // std::cout << "\n\n" << divCurrlen << "\n\n";
            std::cout << "\nlen:\t" << std::dec << (uint64_t)validlen << "\n\n";
            
            // calculate MerkleRoot
            // while(currlen != 0 || currlen != 1) {
                
                
                // update current length of leaves until MerkleRoot
            //     currlen /= 2;
            //     j++;
            // }
        }
}; // namespace MerkleTree
