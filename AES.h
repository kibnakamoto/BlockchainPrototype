/* Author: Taha Canturk
 *  Github: Kibnakamoto
 *  Repisotory: BlockchainPrototype
 *  Start Date: March, 5, 2022
 *  Last Update: May 1, 2022
 */

#ifndef AES_H
#define AES_H

#include <iostream>
#include <stdint.h>
#include <string.h>
#include <sstream>
#include <iomanip>

class AES
{
    // operations of aes 256, 128, 192
    class OPS_AES
    {
        /* ENCRYPTION/DECRYPTION */
        private:
            // Rijndael's S-box as a 2-dimentional matrix
            const uint8_t sbox[16][16] = {
                {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 
                0x2B, 0xFE, 0xD7, 0xAB, 0x76}, {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59,
                0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0}, {0xB7,
                0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 
                0x71, 0xD8, 0x31, 0x15}, {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05,
                0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75}, {0x09, 0x83,
                0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29,
                0xE3, 0x2F, 0x84}, {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
                0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF}, {0xD0, 0xEF, 0xAA,
                0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
                0x9F, 0xA8}, {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC,
                0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2}, {0xCD, 0x0C, 0x13, 0xEC,
                0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
                0x73}, {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
                0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB}, {0xE0, 0x32, 0x3A, 0x0A, 0x49,
                0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4,
                0xEA, 0x65, 0x7A, 0xAE, 0x08}, {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
                0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A}, {0x70,
                0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
                0x86, 0xC1, 0x1D, 0x9E}, {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E,
                0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF}, {0x8C, 0xA1,
                0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 
                0x54, 0xBB, 0x16}};
            
            // Rijndael's inverse S-box as a 2-dimentional matrix
            const uint8_t inv_sbox[16][16] = {
                {0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
                0x9e, 0x81, 0xf3, 0xd7, 0xfb}, {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
                0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, {0x54,
                0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0xb,
                0x42, 0xfa, 0xc3, 0x4e}, {0x8, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
                0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, {0x72, 0xf8,
                0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
                0x65, 0xb6, 0x92}, {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, {0x90, 0xd8, 0xab,
                0x0, 0x8c, 0xbc, 0xd3, 0xa, 0xf7, 0xe4, 0x58, 0x5, 0xb8, 0xb3, 0x45,
                0x6}, {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0xf, 0x2, 0xc1, 0xaf, 
                0xbd, 0x3, 0x1, 0x13, 0x8a, 0x6b}, {0x3a, 0x91, 0x11, 0x41, 0x4f,
                0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
                {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37,
                0xe8, 0x1c, 0x75, 0xdf, 0x6e}, {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29,
                0xc5, 0x89, 0x6f, 0xb7, 0x62, 0xe, 0xaa, 0x18, 0xbe, 0x1b}, {0xfc,
                0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
                0x78, 0xcd, 0x5a, 0xf4}, {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x7, 0xc7,
                0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, {0x60, 0x51,
                0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0xd, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 
                0xc9, 0x9c, 0xef}, {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
                0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, {0x17, 0x2b, 0x4,
                0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21,
                0xc, 0x7d}};
        public:
            // round constant array
            const uint8_t rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
                                      0x40, 0x80, 0x1b, 0x36};

            
            // Galois Field Multipication 2^8
            uint8_t GF256(uint8_t x, uint8_t y)
            {
                /* implemented with bitmasking for efficient and safe 
                   cryptographical use. */
                uint8_t p=0;
                for(int c=0;c<8;c++) {
                    p ^= (uint8_t)(-(y&1)&x);
                    x = (uint8_t)((x<<1) ^ (0x11b & -((x>>7)&1)));
                    y >>= 1;
                }
                return p;
            }
            
            // bitwise circular-left-shift operator for rotating by 8 bits.
            uint32_t rotword(uint32_t x)
            {
                return (x<<8)|(x>>32-8);
            }
            
            /* ENCRYPTION */
            uint8_t** subBytes(uint8_t** b, uint8_t Nb)
            {
                /* seperates hex byte into 2 4 bits and use them as index to
                   sub in values as index of s-box */
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++) {
                        uint8_t low_mask = b[r][c] & 0x0fU;
                        uint8_t high_mask = b[r][c] >> 4;
                        b[r][c] = sbox[high_mask][low_mask];
                    }
                }
                return b;
            }
            
            // shifting rows
            uint8_t** shiftrows(uint8_t** state, uint8_t Nb)
            {
               // to stop values from overriding, use 2 arrays with the same values
               uint8_t pre_state[4][Nb];
               for(int r=1;r<4;r++) {
                   for(int c=0;c<Nb;c++)
                       pre_state[r][c] = state[r][c];
               }
                // ShiftRows operation. First row is not changed
                for(int r=1;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = pre_state[r][(r+c)%4];
                }
                return state;
            }
            
            uint8_t** mixcolumns(uint8_t** state, uint8_t Nb)
            {
                // lambda function xtime
                auto xtime = [] (uint8_t x)
                {
                    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
                };
                
                for(int c=0;c<Nb;c++) {
                    // create temporary array to stop overriding
                    uint8_t tmpS[4] = {state[0][c], state[1][c], state[2][c], 
                                       state[3][c]};
                    
                    // MixColumns operation from AES proposal
                    uint8_t Tmp = (tmpS[0] ^ tmpS[1] ^ tmpS[2] ^ tmpS[3]);
                    uint8_t Tm =  (tmpS[0] ^ tmpS[1]) ; Tm = xtime(Tm); 
                    state[0][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[1] ^ tmpS[2]) ; Tm = xtime(Tm); 
                    state[1][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[2] ^ tmpS[3]) ; Tm = xtime(Tm);
                    state[2][c] ^=  (Tm ^ Tmp);
                    Tm =       (tmpS[3] ^ tmpS[0]) ; Tm = xtime(Tm);
                    state[3][c] ^=  (Tm ^ Tmp);
                }
                return state;
            }
            
        private:
            uint32_t sub_int(uint32_t y)
            {
                return sbox[(y&0xff)>>4][y&0x0fU];
            }
            
        public:
            uint32_t subword(uint32_t x)
            {
                return (sub_int(x>>24)<<24) | (sub_int((x>>16)&0xff)<<16) |
                       (sub_int((x>>8)&0xff)<<8) | (sub_int(x&0xff)); 
            }
            
            uint8_t** addroundkey(uint8_t** state, uint32_t* w, uint32_t rnd,
                                  uint8_t Nb)
            {
                for(int c=0;c<Nb;c++) {
                    uint32_t w_index = w[rnd*4+c];
                    state[0][c] ^= (w_index >> 24) & 0xff;
                    state[1][c] ^= (w_index >> 16) & 0xff;
                    state[2][c] ^= (w_index >> 8) & 0xff;
                    state[3][c] ^= w_index & 0xff;
                }
                return state;
            }
        
            /* DECRYPTION */
            
            uint8_t** inv_subBytes(uint8_t** state, uint8_t Nb)
            {
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++) {
                        uint8_t low_mask = state[r][c] & 0x0fU;
                        uint8_t high_mask = state[r][c] >> 4;
                        state[r][c] = inv_sbox[high_mask][low_mask];
                    }
                }
                return state;
            }
            
            uint8_t** inv_shiftrows(uint8_t** state, uint8_t Nb)
            {
                // to stop values from overriding, duplicate matrix
               uint8_t inv_pre_state[4][Nb];
               for(int r=1;r<4;r++) {
                   for(int c=0;c<Nb;c++)
                       inv_pre_state[r][c] = state[r][c];
               }
                

                // shift rows. First row is not changed
                for(int r=1;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][(r+c)%4] = inv_pre_state[r][c];
                }
                return state;
            }
            
            uint8_t** inv_mixcolumns(uint8_t** state, uint8_t Nb)
            {
                uint8_t s_mixarr[4] = {0x0e, 0x0b, 0x0d, 0x09};
                for(int c=0;c<Nb;c++) {
                    // to stop matrix from overriding, use temporrary array
                    uint8_t tmp_state[4] = {state[0][c], state[1][c], state[2][c],
                                            state[3][c]};
                    state[0][c] = (GF256(tmp_state[0], s_mixarr[0]) ^
                                   GF256(tmp_state[1], s_mixarr[1]) ^
                                   GF256(tmp_state[2], s_mixarr[2]) ^
                                   GF256(tmp_state[3], s_mixarr[3]));
                    state[1][c] = (GF256(tmp_state[0], s_mixarr[3]) ^
                                   GF256(tmp_state[1], s_mixarr[0]) ^
                                   GF256(tmp_state[2], s_mixarr[1]) ^
                                   GF256(tmp_state[3], s_mixarr[2]));
                    state[2][c] = (GF256(tmp_state[0], s_mixarr[2]) ^
                                   GF256(tmp_state[1], s_mixarr[3]) ^
                                   GF256(tmp_state[2], s_mixarr[0]) ^
                                   GF256(tmp_state[3], s_mixarr[1]));
                    state[3][c] = (GF256(tmp_state[0], s_mixarr[1]) ^
                                   GF256(tmp_state[1], s_mixarr[2]) ^ 
                                   GF256(tmp_state[2], s_mixarr[3]) ^
                                   GF256(tmp_state[3], s_mixarr[0]));
                }
                return state;
            }
            
        protected:
           // KeyExpansion
           uint32_t* keyExpansion(std::shared_ptr<uint8_t> key, uint32_t* w, uint8_t Nb,
                                  uint8_t Nk, uint8_t Nr)
            {
                uint32_t temp;
                int i=0;
                do {
                    w[i] = ((uint32_t)key.get()[4*i]<<24) | (key.get()[4*i+1]<<16) |
                           (key.get()[4*i+2]<<8) | key.get()[4*i+3];
                    i++;
                } while(i<Nk);
                i=Nk;
                
                // rcon values. initialize twice so it doesn't override
                uint32_t tmp_rcon[11];
                for(int c=1;c<11;c++) {
                    tmp_rcon[c] = (uint8_t)(rcon[c] & 0xff)<<24;
                }
                
                while(i<Nb*(Nr+1)) {
                    temp = w[i-1];
                    if(i%Nk == 0) {
                        temp = subword(rotword(temp)) ^ (uint32_t)tmp_rcon[i/Nk];
                    }
                    else if(Nk>6 && i%Nk == 4) {
                        temp = subword(temp);
                    }
                    w[i] = temp ^ w[i-Nk];
                    i++;
                }
                return w;
            }
            
            uint8_t* cipher(uint8_t* input, uint8_t* output, uint32_t* w, 
                            uint8_t Nb, uint8_t Nk, uint8_t Nr)
            {
                // declare state matrix
                uint8_t** state = nullptr;
                state = new uint8_t*[4];
                for(int r=0;r<4;r++) {
                    state[r] = new uint8_t[Nb];
                }
                
                // put 1-dimentional array values to a 2-dimentional matrix
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = input[r+4*c];
                }
                
                // call functions to manipulate state matrix
                addroundkey(state, w, 0, Nb);
                for(int rnd=1;rnd<Nr;rnd++) {
                    subBytes(state, Nb);
                    shiftrows(state, Nb);
                    mixcolumns(state, Nb);
                    addroundkey(state, w, rnd, Nb);
                }
                subBytes(state, Nb);
                shiftrows(state, Nb);
                addroundkey(state, w, Nr, Nb);
            
                // copy state array to output
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        output[r+4*c] = state[r][c];
                }
                for(int c=0;c<4;c++) {
                   delete[] state[c];
                }
                delete[] state;
                return output;
            }
            
            std::string encrypt(std::string user_in,std::shared_ptr<uint8_t> key, uint8_t Nb,
                                uint8_t Nk, uint8_t Nr)
            {
                // declare arrays
                uint8_t input[4*Nb];
                uint8_t output[4*Nb];
                uint32_t w[Nb*(Nr+1)]; // key schedule
                
                // append user input to 1-dimentional array
                for(int c=0;c<4*Nb;c++) {
                    input[c] = user_in[c];
                }
                
                // call KeyExpansion and Cipher function
                keyExpansion(key, w, Nb, Nk, Nr);
                cipher(input, output, w, Nb, Nk, Nr);

                // convert output array to hex string
                std::stringstream ss;
                for (int c=0;c<4*Nb;c++)
                {
                    ss << std::setfill('0') << std::setw(2) << std::hex
                       << (uint16_t)output[c];
                }
            	return ss.str();
            }
            
            uint8_t* invCipher(uint8_t* input, uint8_t* output, uint32_t* w,
                               uint8_t Nb, uint8_t Nk, uint8_t Nr)
            {
                // declare state matrix as a 2d C++ pointer
                uint8_t** state = nullptr;
                state = new uint8_t*[4];
                for(int r=0;r<4;r++) {
                    state[r] = new uint8_t[Nb];
                }
                
                // 1d input to 2d matrix
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        state[r][c] = input[r+4*c];
                }
                
                addroundkey(state, w, Nr, Nb);
                for(int rnd=Nr-1;rnd>0;rnd--) {
                    inv_shiftrows(state, Nb);
                    inv_subBytes(state, Nb);
                    addroundkey(state, w, rnd, Nb);
                    inv_mixcolumns(state, Nb);
                }
                
                inv_shiftrows(state, Nb);
                inv_subBytes(state, Nb);
                addroundkey(state, w, 0, Nb);
                
                // 2d array to 1d array
                for(int r=0;r<4;r++) {
                    for(int c=0;c<Nb;c++)
                        output[r+4*c] = state[r][c];
                }
                return output;
            }
            
            std::string decrypt(std::string user_in, std::shared_ptr<uint8_t> key, uint8_t Nb,
                                uint8_t Nk, uint8_t Nr)
            {
                // declare single-dimentional arrays
                uint8_t output[4*Nb];
                uint8_t input[4*Nb];
                uint32_t w[Nb*(Nr+1)];
                std::stringstream conv;
                for(int c=0;c<user_in.length();c+=2) {
                    conv << std::hex << user_in.substr(c,2);
                    int32_t uint8;
                    conv >> uint8;
                    input[c/2] = uint8 & 0xffU;
                    conv.str(std::string());
                    conv.clear();
                }
                
                // create key schedule and decrypt
                keyExpansion(key, w, Nb, Nk, Nr); 
                invCipher(input, output, w, Nb, Nk, Nr);
                std::string str = "";
                for(int c=0;c<4*Nb;c++) {
                    str += output[c];
                }
                return str;
            }
        public:
            std::string multi_block_process_enc(std::string user_in, std::shared_ptr<uint8_t>
                                                key, uint8_t Nb, uint8_t Nk,
                                                uint8_t Nr)
            {
                // pad message so that length is a multiple of block size(16)
                uint32_t msg_blen = user_in.length() + 16-user_in.length()%16;
                if(user_in.length()%16 == 0) {
                    msg_blen-=16;
                }
                std::stringstream ss;
                ss << user_in << std::setfill('0') << std::setw(msg_blen) << "";
                std::string new_input[msg_blen/16];
                int32_t k=-1;
                std::string final_val = "";
                
                // seperate message into blocks of 16
                for(int c=0;c<msg_blen;c+=16) {
                    k++;
                    if(k<msg_blen/16) {
                        new_input[k] = ss.str().substr(c,16);
                    }
                }
                for(int c=0;c<msg_blen/16;c++) {
                    final_val += encrypt(new_input[c], key, Nb, Nk, Nr);
                }
                return final_val;
            }
            
            std::string multi_block_process_dec(std::string user_in, std::shared_ptr
                                                <uint8_t> key, uint8_t Nb, uint8_t Nk,
                                                uint8_t Nr)
            {
                std::string new_input[user_in.length()/32];
                int k=-1;
                std::string final_val = "";
                
                // input length has to be a multiple of 16 bytes
                if(user_in.length()%32 != 0) {
                    std::cout << "ERROR:\tlength is not a multiple of 32";
                    exit(EXIT_FAILURE);
                }
                
                // seperate message into blocks of 32 hex digits
                for(int c=0;c<user_in.length();c+=32) {
                    k++;
                    new_input[k] = user_in.substr(c,32);
                }
                k=user_in.length()/32;
                for(int c=0;c<k;c++) {
                    final_val += decrypt(new_input[c], key, Nb, Nk, Nr);
                }
                return final_val;
            }
    };
    
    public:
    class AES128
    {
        // AES algorithm size for AES128
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 4;
            const uint8_t Nr = 10;
        public:
            std::string encrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
    };
    
    class AES192
    {
        // AES algorithm size for AES192
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 6;
            const uint8_t Nr = 12;
        public:
            std::string encrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
        
    };
    
    class AES256
    {
        // AES algorithm size for AES256
        protected:
            const uint8_t Nb = 4;
            const uint8_t Nk = 8;
            const uint8_t Nr = 14;
        public:
            std::string encrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_enc(user_in, key, Nb, Nk, Nr);
            }
            
            std::string decrypt(std::string user_in, std::shared_ptr<uint8_t> key)
            {
                OPS_AES Operation = OPS_AES();
                return Operation.multi_block_process_dec(user_in, key, Nb, Nk, Nr);
            }
    };
};

#endif /* AES_H_ */
