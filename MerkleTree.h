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
            bool odd = true;
            __uint128_t validlen = 2;
            while(validlen < len) {
                validlen*=2;
            }
            
            while(len<validlen) { // append it 2, 4, 8... times
                uint64_t* oddZfill = new uint64_t[8];
                oddZfill = sha512("00000000");
                mempool.push_back(oddZfill);
                len++; // update len
            }
                // std::cout << "\n\n" << divCurrlen << "\n\n";
            std::cout << "\nlen:\t" << std::dec << len << "\n\n";
            
            // calculate MerkleRoot
            uint64_t currlen = len;
            while(len/2 != 1) {
                
                
                // update current length of leaves until MerkleRoot
                currlen /= 2;
            }
        }
}; // namespace MerkleTree
