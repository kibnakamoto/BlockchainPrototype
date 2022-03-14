#include <stdint.h>
#include <vector>
#include <string>
#include "sha512.h"

class MerkleTree
{
    public:
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
            while(divisible != true) {
                uint64_t* oddZfill = new uint64_t[8];
                oddZfill = sha512("00000000");
                divCurrlen/=2;
                if(divCurrlen%2 != 0) {
                    mempool.push_back(oddZfill);
                    len++;
                }
                divisible = (divCurrlen == 0);
                mempool.push_back(oddZfill);
                len++;
                std::cout << std::dec << divCurrlen << " ";
            }
            std::cout << "\nlen:\t" << std::dec << len << "\n\n";
            /*
             * create newlen for adding zero hashes whenever there aren't enough
             * leaves in the creation of the MerkleRoot. Do not add it to mempool
             */
            // if length not a multiple of 4, there aren't enough leaves
            uint64_t j=0;
            
            // calculate MerkleRoot
            // while(currlen >= 0) {
                
                
                // update current length of leaves until MerkleRoot
            //     currlen /= 2;
            //     j++;
            // }
        }
};
