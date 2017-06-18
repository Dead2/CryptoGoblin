#ifdef HAVE_ALWAYS_INLINE
#  define ALWAYS_INLINE __attribute__((always_inline))
#else
#  define ALWAYS_INLINE
#endif

#ifdef HAVE_FLATTEN
#  define FLATTEN __attribute__((flatten))
#else
#  define FLATTEN
#endif

#ifdef HAVE_ALIGNED
#  define ALIGN16 __attribute__((aligned (16)))
#else
#  define ALIGN16
#endif

