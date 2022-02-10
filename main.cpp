/*
* This implementation is for modern c++. Some of the methods used are after c++17
* so if you are using an older version, make some tweaks.
* 
*/

#include <iostream>
#include <string>
#include "__uint256_t.h"
#include "sha512.h"

int main()
{
    /* iterate each value of mempool using this method, replace string abc 
       with the that needs to be hashed. Since mempool is a hash array, no 
       need to hash it again */
    IntTypes int_type = IntTypes();
    uint64_t SingleMempoolHash[8];
    memcpy(SingleMempoolHash, sha512("abc"), sizeof(uint64_t)<<3);
    for(uint64_t c : SingleMempoolHash) {
        std::cout << std::hex << c << " ";
    }
    auto [fst, snd] = int_type.__uint256_t(SingleMempoolHash);
    for(int c=0;c<0;c++) {
        fst;
        snd;
    }

    
    return 0;
}
