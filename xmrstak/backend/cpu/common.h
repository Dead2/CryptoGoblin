#ifndef COMMON_H
#define COMMON_H

#define XMR_HASHBITLEN 256U
#define XMR_DATABITLEN 1600UL


#ifdef HAVE_ALWAYS_INLINE
#  define ALWAYS_INLINE __attribute__((always_inline))
#else
# define ALWAYS_INLINE
#endif

#ifdef HAVE_FLATTEN
# ifdef DO_FLATTEN1
#  define FLATTEN __attribute__((flatten))
# else
#  define FLATTEN
# endif
# ifdef DO_FLATTEN2
#  define FLATTEN2 __attribute__((flatten))
# else
#  define FLATTEN2
# endif
# ifdef DO_FLATTEN3
#  define FLATTEN3 __attribute__((flatten))
# else
#  define FLATTEN3
# endif
#else
# define FLATTEN
# define FLATTEN2
# define FLATTEN3
#endif

#ifdef HAVE_ALIGNED
#  define ALIGN(x)  __attribute__((aligned (x)))
#else
# define ALIGN(x)
#endif

#ifdef HAVE_OPTIMIZE
#  define OPTIMIZE(x)  __attribute__((optimize (x)))
#else
# define OPTIMIZE(x)
#endif

#ifdef HAVE_TARGET_CLONES
#  define TARGETS(x) __attribute__((target_clones(x)))
#else
#  define TARGETS(x)
#endif


#ifdef DEBUG
#include <stdio.h>
static void print_hex_memory(void *mem, int len) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  for (i=0;i<len;i++) {
    printf("0x%02x ", p[i]);
    if ((i%16==0) && i)
      printf("\n");
  }
  printf("\n");
}
#endif //DEBUG

#endif
