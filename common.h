#ifndef COMMON_H
#define COMMON_H

#ifdef HAVE_ALWAYS_INLINE
#  define ALWAYS_INLINE __attribute__((always_inline))
#else
# define ALWAYS_INLINE
#endif

#ifdef HAVE_FLATTEN
# ifdef DO_FLATTEN
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
#  define ALIGN16  __attribute__((aligned (16)))
#  define ALIGN32  __attribute__((aligned (32)))
#  define ALIGN64  __attribute__((aligned (64)))
#  define ALIGN128 __attribute__((aligned (128)))
#else
# define ALIGN16
# define ALIGN32
# define ALIGN64
# define ALIGN128
#endif

#ifdef HAVE_TARGET_CLONES
#  define TARGETS(x) __attribute__((target_clones(x)))
#else
#  define TARGETS(x)
#endif

#endif
