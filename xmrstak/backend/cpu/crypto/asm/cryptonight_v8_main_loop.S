#define ALIGN .align
.intel_syntax noprefix
#ifdef __APPLE__
#   define FN_PREFIX(fn) _ ## fn
.text
#else
#   define FN_PREFIX(fn) fn
.section .text
#endif
.global FN_PREFIX(cryptonight_v8_mainloop_ivybridge_asm)
.global FN_PREFIX(cryptonight_v8_mainloop_ryzen_asm)
.global FN_PREFIX(cryptonight_v8_double_mainloop_sandybridge_asm)

ALIGN 8
FN_PREFIX(cryptonight_v8_mainloop_ivybridge_asm):
	sub rsp, 48
#ifdef __MINGW32__
	#include "cryptonight_v8_main_loop_ivybridge_win64.inc"
#else
	mov rcx, rdi
	#include "cryptonight_v8_main_loop_ivybridge_linux.inc"
#endif
	add rsp, 48
	ret 0

ALIGN 8
FN_PREFIX(cryptonight_v8_mainloop_ryzen_asm):
	sub rsp, 48
#ifdef __MINGW32__
	#include "cryptonight_v8_main_loop_ryzen_win64.inc"
#else
	mov rcx, rdi
	#include "cryptonight_v8_main_loop_ryzen_linux.inc"
#endif
	add rsp, 48
	ret 0

ALIGN 16
FN_PREFIX(cryptonight_v8_double_mainloop_sandybridge_asm):
	sub rsp, 48
#ifdef __MINGW32__
	#include "cryptonight_v8_double_main_loop_sandybridge_win64.inc"
#else
	mov rcx, rdi
	mov rdx, rsi
	#include "cryptonight_v8_double_main_loop_sandybridge_linux.inc"
#endif
	add rsp, 48
	ret 0
