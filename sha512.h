/*
 *  github: kibnakamoto
 *   Created on: Dec. 5, 2021
 *      Author: Taha Canturk
 *       Finalized: Jan. 5 2022
 *        More Info: github.com/kibnakamoto/sha512.cpp/blob/main/README.md
 */

#ifndef SHA512_H_
#define SHA512_H_

#include <iostream>
#include <string>
#include <cstring>
#include <stdint.h>
#include <iomanip>

// choice = (x ∧ y) ⊕ (¯x ∧ z)
inline uint64_t Ch(uint64_t e, uint64_t f, uint64_t g) {
    return ((e bitand f)xor(~e bitand g));
}
// #define Ch(x,y,z) ((x bitand y)xor(~x bitand z))

// // majority = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
inline uint64_t Maj(uint64_t a, uint64_t b, uint64_t c) {
    return ((a & b)^(a & c)^(b & c));
}

// // binary operators
inline uint64_t Shr(uint64_t x, unsigned int n) {
    return (x >> n);
}
inline uint64_t Rotr(uint64_t x, unsigned int n) {
    return ( (x >> n)|(x << (sizeof(x)<<3)-n) );
}


// length which is __uint128_t in 2 uint64_t integers
inline std::pair<uint64_t,uint64_t> to2_uint64(__uint128_t source) {
    constexpr const __uint128_t bottom_mask = (__uint128_t{1} << 64) - 1;
    constexpr const __uint128_t top_mask = ~bottom_mask;
    return {source bitand bottom_mask, Shr((source bitand top_mask), 64)};
}

class SHA512
{
    protected:
        // 80 64 bit unsigned constants for sha512 algorithm
        const uint64_t K[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
            0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
            0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
            0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
            0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
            0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 
            0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
            0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
            0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
            0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
            0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
            0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
            0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
            0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
            0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
            0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
            0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
            0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
            0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
            0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
            0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};
        
        // initialize hash values
        uint64_t H[8] = {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
                         0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
                         0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
                         0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
            
            // transform
            uint64_t* transform(uint64_t* TMP)
            {
                // initialize hash values
                uint64_t V[8];
                memcpy(V, H, sizeof(uint64_t)*8);

                // create message schedule
                for (int c=16;c<80;c++)
                {
                    // σ0 = (w[c−15] ≫≫ 1) ⊕ (w[c−15] ≫≫ 8) ⊕ (w[c−15] ≫ 7)
                    uint64_t s0 = Rotr(TMP[c-15],1) xor Rotr(TMP[c-15],8) xor 
                                       Shr(TMP[c-15],7);
                    
                    // σ1 = (w[c−2] ≫≫ 19) ⊕ (w[c−2] ≫≫ 61) ⊕ (w[c−2] ≫ 6)
                    uint64_t s1 = Rotr(TMP[c-2],19) xor Rotr(TMP[c-2],61) xor 
                                  Shr(TMP[c-2],6);
                    
                    // uint64_t does binary addition 2^64.
                    // w[c] = w[c−16] [+] σ0 [+] w[c−7] [+] σ1
                    TMP[c] = TMP[c-16] + s0 + TMP[c-7] + s1;
                }
                
                for (int c=0;c<80;c++)
                {
                    // Σ0 = (a ≫≫ 28) ⊕ (a ≫≫ 34) ⊕ (a ≫≫ 39)
                    uint64_t S0 = Rotr(V[0], 28) xor Rotr(V[0], 34) xor Rotr(V[0], 39);
                    
                    // T2 = Σ0 + Maj
                    uint64_t temp2 = S0 + Maj(V[0], V[1], V[2]);
                    
                    // Σ1 = (e ≫≫ 14) ⊕ (e ≫≫ 18) ⊕ (e ≫≫ 41)
                    uint64_t S1 = Rotr(V[4], 14) xor Rotr(V[4], 18) xor Rotr(V[4], 41);
                    
                    // T1 = h + Σ1 + Ch[e,f,g] + K[c] + W[c]
                    uint64_t temp1 = V[7] + S1 + Ch(V[4], V[5], V[6]) + K[c] + TMP[c];
                    
                    // modify hash values
                    V[7] = V[6];
                    V[6] = V[5];
                    V[5] = V[4];
                    V[4] = V[3] + temp1;
                    V[3] = V[2];
                    V[2] = V[1];
                    V[1] = V[0];
                    V[0] = temp1 + temp2;
                    for(int i=0;i<8;i++) {
                        std::cout << "V[" << std::dec << i << "]:\t" << std::hex
                                  << V[i] << "\tc:\t" << std::dec << c << std::endl;
                    }
                }
                for(int c=0;c<8;c++) {
                    H[c] += V[c];
                }

                return H;
            }
        
    public:
        std::string Sha512(std::string msg)
        {
            
        	// length in bytes.
            __uint128_t len = msg.length();
            
            // length is represented by a 128 bit unsigned integer
            __uint128_t bitlen = len << 3;
            
            // padding with zeros
            unsigned int padding = ((1024-(bitlen+1)-128) % 1024)-7; // in bits
            padding /= 8; // in bytes.
            __uint128_t blockBytesLen = padding+len+17;
            uint8_t WordArray[blockBytesLen];
            memset(WordArray, 0, blockBytesLen);
            for (__uint128_t c=0;c<len;c++) {
                WordArray[c] = msg.c_str()[c];
            }
            WordArray[len] = (uint8_t)0x80; // append 10000000.
            
            uint64_t W[blockBytesLen/8];
            // pad W with zeros
            for (int c=0; c<blockBytesLen/8; c++) {
                W[c] = 0x00;
            }
            
            // 8 bit array values to 64 bit array using 64 bit integer array.
            for (int i=0; i<len/8+1; i++) {
                W[i] = (uint64_t)WordArray[i*8]<<56;
                for (int j=1; j<=6; j++)
                    W[i] = W[i]|( (uint64_t)WordArray[i*8+j]<<(7-j)*8);
                W[i] = W[i]|( (uint64_t)WordArray[i*8+7] );
            }
            
            // append 128 bit length as 2 uint64_t's as a big endian
            auto [fst, snd] = to2_uint64(bitlen);
            W[Shr(padding+len+1,3)+1] = fst;
            W[Shr(padding+len+1,3)+2] = snd;
            
            /* multi-block processing start */
            uint64_t TMP[80];
            for(int c=0;c<80;c++) {
                TMP[c] = 0x00;
            }
            
            // multi-block processing
            for(int c=0;c<blockBytesLen/128;c++) {
                for(int i=0;i<16;i++)
                    TMP[i] = W[i+16*c];
                transform(TMP);
            }
            
            std::stringstream ss;
            for (int c=0;c<8;c++)
            {
                ss << std::setfill('0') << std::setw(16) << std::hex << (H[c]|0);
            }
        	return ss.str();
        }
};

std::string sha512(std::string input) {
    SHA512 hash;
    return hash.Sha512(input);
}

#endif /* SHA512_H_ */
