/*
* This implementation is for modern c++. Some of the methods used are after c++17
* so if you are using an older version, make some tweaks.
* 
*/

#include <iostream>
#include <string>
#include "bigInt.h"
#include "sha512.h"

int main()
{
    /* iterate each value of mempool using this method, replace string abc 
       with the that needs to be hashed. Since mempool is a hash array, no 
       need to hash it again */
    IntTypes int_type = IntTypes();
    uint64_t SingleMempoolHash64[8];
    uint32_t SingleMempoolHash32[8] {0xddaf35a1, 0x93617aba, 0xcc417349, 
                                     0xae204131, 0x12e6fa4e, 0x89a97ea2,
                                     0x0a9eeee6, 0x4b55d39a};
    memcpy(SingleMempoolHash64, sha512("abc"), sizeof(uint64_t)<<3);
    for(uint64_t c : SingleMempoolHash64) {
        std::cout << std::hex << c << " ";
    }
    auto [fst, snd, trd, frd] = int_type.__uint512_t(SingleMempoolHash64);
    for(int c=0;c<0;c++) {
        fst;
        snd;
        trd;
        frd;
    }

    
    return 0;
}
