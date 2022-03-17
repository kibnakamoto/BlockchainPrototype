
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
            bool divisible;
            if(len%2 == odd) { // make sure len is not odd
                uint64_t* oddZfill = new uint64_t[8];
                oddZfill = sha512("00000000");
                mempool.push_back(oddZfill);
                len++;
            }
            uint64_t divCurrlen = len;
            bool divs;
            int amountofLoop = 0;
            while (divCurrlen != 0) {
                divCurrlen /= 2;
                amountofLoop++;
                for(int c=0;c<amountofLoop*2;c++) {
                    uint64_t* oddZfill = new uint64_t[8];
                    oddZfill = sha512("00000000");
                    mempool.push_back(oddZfill);
                    len++; // update len
                }
                divs = (divCurrlen/2) % 2 == 0;
                if(divs != true) {
                    mempool.push_back(oddZfill);
                    len++; // update len
                }
                std::cout << "\n\n" << divCurrlen << "\n\n";
            }
            std::cout << "\nlen:\t" << std::dec << len << "\n\n";
            
            // calculate MerkleRoot
            // while(currlen >= 0) {
                
                
                // update current length of leaves until MerkleRoot
            //     currlen /= 2;
            //     j++;
            // }
        }
}; // namespace MerkleTree


