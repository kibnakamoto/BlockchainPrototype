// Copyright (c) 2022 Taha Canturk
// Distributed under the GPL-3.0 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html


#ifndef CONDITIONS_H_
#define CONDITIONS_H_

// if required integer types not defined
#if !defined(UINT8_MAX)
    using uint8_t = unsigned char;
#elif !defined(UINT32_MAX)
    using uint32_t = unsigned int;
#elif !defined(UINT64_MAX)
    using uint64_t = unsigned long long;
#elif !defined(INT32_MAX)
    using int32_t = int;    
#endif /* INT32_MAX */

// global boolean for ui working on either console or terminal
// if unix based operating system, use terminal
#if  defined(__unix__) || defined(__MACH__) || defined(__linux__)
    bool console_ui_activate = false;
#else
    bool console_ui_activate = true;
#endif /* __linux__ */

#endif /* CONDITIONS_H_ */
