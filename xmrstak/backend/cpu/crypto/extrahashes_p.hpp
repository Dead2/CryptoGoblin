/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting work.
  *
  */

extern "C"
{
#include "c_blake256.h"
#include "c_skein.h"
}
#include "groestl.hpp"
#include "jh.hpp"

void do_blake_hash(const void* input, char* output) {
    blake256_hash((uint8_t*)output, (const uint8_t*)input, 200);
}

void do_groestl_hash(const void* input, char* output) {
    xmr_groestl((const uint8_t*)input, (uint8_t*)output);
}

void do_jh_hash(const void* input, char* output) {
    xmr_jh256((const uint8_t*)input, (uint8_t*)output);
}

void do_skein_hash(const void* input, char* output) {
    xmr_skein((const uint8_t*)input, (uint8_t*)output);
}

void (* const extra_hashes[4])(const void *, char *) = {do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash};
