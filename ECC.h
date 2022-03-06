#include <iostream>
#include <stdint.h>
#include <string.h> // for memcpy
#include "sha512.h"

#define PVAL_brainpoolp512r1 (0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3)

// finite fields
class Galois_Fields
{
    public:
        // Galois Field Multipication 2^8
        uint8_t GF256(uint8_t x, uint8_t y)
        {
            // implemented with bitmasking for efficient and safe cryptographical use.
            uint8_t p=0;
            for(int c=0;c<8;c++) {
                p ^= (uint8_t)(-(y&1)&x);
                x = (uint8_t)((x<<1) ^ (0x11b & -((x>>7)&1)));
                y >>= 1;
            }
            return p;
        }
        
        // Galois Field Multipication 2 = xor
};

// Elliptic Curve Cryptography Encryption
class ECC
{
    public:
        uint64_t* brainpoolp512r1(uint64_t* private_key, uint64_t* public_key)
        {
            SHA512 hash = SHA512();
            Galois_Fields galois_field = Galois_Fields();
            // __uint128_t p[4] = {0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07, 
            //                     0xCB308DB3B3C9D20ED6639CCA70330871,
            //                     0x7D4D9B009BC66842AECDA12AE6A380E6,
            //                     0x2881FF2F2D82C68528AA6056583A48F3};
            std::cout << "test";
            __uint128_t p[4];
            for(int c=0;c<4;c++) {
                // p[c];
                // p[c] = PVAL_brainpoolp512r1 >> ((512-128)/((c+4)%4));
                std::cout << ((512-128)/((c+4)%4));
            }
            // {4599554755319692295, 15448363540090652785, 12595900938455318758, 2930260431521597683}

            // Domain Parameters for brainpoolp512r1
            //   p = AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308
            //   717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3
            //   A = 7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863
            //   BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA
            //   B = 3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117
            //   A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723
            //   x = 81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D009
            //   8EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822
            //   y = 7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F81
            //   11B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892
            //   q = AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308
            //   70553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069
            //   h = 1
            
            return nullptr;
        }
};
