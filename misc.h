#ifndef __misc_h__
#define __misc_h__

#include <string>
#include <stdint.h>
#include <cstdlib>

namespace loaded {

unsigned short in_cksum (unsigned short *ptr, int nbytes);

int parse_config(const std::string &path);

uint16_t cksum_update_128(uint32_t oval[4], uint32_t nval[4], uint16_t osum);
uint16_t cksum_update_32(uint32_t oval, uint32_t nval, uint16_t osum);

int balance_cpus();

extern std::string strategy;

}

#endif

