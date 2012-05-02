#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>

// bignum size
#define BN_BITS 64
#define BN_SZ (BN_BITS/8/sizeof(unsigned int))

// Big number math functions
// NOTE: These functions can only handle unsigned numbers!

typedef unsigned int BIGNUM[BN_SZ];
typedef unsigned int *BIGNUM_P;

/**
 * Add two BIGNUMs together.
 *
 * Adds the BIGNUMs <i>a</i> and <i>b</i> together, storing the result in <i>out</i>.
 *
 * Operation: <i>out</i> = <i>a</i> + <i>b</i>
 *
 * @param a First operand
 * @param b Second operand
 * @param out Output
 */
void bn_add(const BIGNUM_P a, const BIGNUM_P b, BIGNUM_P out)
{
	size_t i;
	unsigned long m = 0;

	for (i=0; i<BN_SZ; i++) {
		m += ((unsigned long)a[i] + (unsigned long)b[i]);
		out[i] = m & UINT_MAX;
		m >>= (sizeof(a[0])*8);
	}
	// detect a stray carry (overflow)
	assert(m == 0);
}

/**
 * Subtract one BIGNUM from another.
 *
 * Subtracts the BIGNUM <i>b</i> from <i>a</i>, storing the result in <i>out</i>.
 *
 * Operation: <i>out</i> = <i>a</i> - <i>b</i>
 *
 * @param a First operand
 * @param b Second operand
 * @param out Output
 */
void bn_sub(const BIGNUM_P a, const BIGNUM_P b, BIGNUM_P out)
{
	size_t i;
	long m = 0;

	for (i=0; i<BN_SZ; i++) {
		m = ((long)a[i] - (long)b[i]) + m;
		out[i] = m & UINT_MAX;
		m >>= (sizeof(a[0])*8);
	}
	// detect stray borrow (underflow)
	assert(m == 0);
}

/**
 * Copy a BIGNUM.
 *
 * Copies the BIGNUM <i>a</i> into <i>out</i> without modifying it.
 *
 * Operation: <i>out</i> = <i>a</i>
 *
 * @param a First operand
 * @param out Output
 */
void bn_copy(const BIGNUM_P a, BIGNUM_P out)
{
	memcpy(out, a, BN_SZ*sizeof(out[0]));
}

/**
 * Clear a BIGNUM.
 *
 * Sets the value of the BIGNUM <i>out</i> to zero.
 *
 * Operation: <i>out</i> = 0
 *
 * @param out Output
 */
void bn_clear(BIGNUM_P out)
{
	memset(out, 0, BN_SZ*sizeof(out[0]));
}

/**
 * Print a BIGNUM in hexadecimal form.
 *
 * @param a Number to print
 */
void bn_printhex(const BIGNUM_P a)
{
	ssize_t i;
	for (i=BN_SZ-1; i>=0; i--) {
		printf("%08X", a[i]);
		if (i != 0) putchar('_');
	}
}

/**
 * Print a BIGNUM in hexadecmial, prefixed with a user specified string and suffixed with a newline.
 *
 * Prints the value of the BIGNUM <i>a</i> on STDOUT, prefixed by the string
 * <i>s</i> and suffixed with a newline.
 *
 * @param s String prefix
 * @param a Number to print
 */
void bn_printhex_s(const char *s, const BIGNUM_P a)
{
	printf("%s", s);
	bn_printhex(a);
	printf("\n");
}

/**
 * Shift the value of a BIGNUM left by one bit.
 *
 * Shifts the value of the BIGNUM <i>a</i> left one bit, storing the result in <i>out</i>.
 *
 * Operation: <i>out</i> = <i>a</i> << 1
 *
 * @param a First operand
 * @param out Output
 */
void bn_shl(const BIGNUM_P a, BIGNUM_P out)
{
	size_t i;
	unsigned long m = 0;

	if (a != out) {
		bn_copy(a, out);
	}

	for (i=0; i<BN_SZ; i++) {
		m += (unsigned long)a[i] << 1;
		out[i] = m & UINT_MAX;
		m >>= (sizeof(a[0]) * 8);
	}
}

/**
 * Shift the value of a BIGNUM right by one bit.
 *
 * Shifts the value of the BIGNUM <i>a</i> left one bit, storing the result in <i>out</i>.
 *
 * Operation: <i>out</i> = <i>a</i> >> 1
 *
 * @param a First operand
 * @param out Output
 */
void bn_shr(const BIGNUM_P a, BIGNUM_P out)
{
	ssize_t i;
	unsigned long m = 0, tmp;

	if (a != out) {
		bn_copy(a, out);
	}

	for (i=BN_SZ-1; i>=0; i--) {
		tmp = a[i];
		out[i] = m + (a[i] >> 1);
		m = (tmp & 1) << ((sizeof(a[0]) * 8)-1);
	}
}


int main(void)
{
	BIGNUM a, b, c;

	printf("sz uini %lu, ulong %lu, ulonglong %lu\n", 
			sizeof(unsigned int),
			sizeof(unsigned long),
			sizeof(unsigned long long)
		  );
	printf("UINT_MAX %08X\n", UINT_MAX);

	printf("BN_SZ = %lu\n", BN_SZ);
	assert(BN_SZ > 0);

	printf("-- clear and add --\n");
	bn_clear(a); bn_clear(b);
	a[0] = b[0] = 0xFFFFFFFF;
//	b[0] = 0x12345678;
	bn_add(a, b, c);
	bn_printhex_s("a   = ", a);
	bn_printhex_s("b   = ", b);
	bn_printhex_s("a+b = ", c);

	printf("-- shift left --\n");
	bn_clear(c);
	c[0] = 0x40000000;
	bn_printhex_s("c     = ", c);
	bn_shl(c, c);
	bn_printhex_s("shl 1 = ", c);
	bn_shl(c, b);
	bn_printhex_s("shlCp = ", b);
	bn_printhex_s("orig  = ", c);

	printf("-- clear and shr --\n");
	bn_clear(c);
	c[1] = 0x1;
	bn_printhex_s("c     = ", c);
	bn_shr(c, c);
	bn_printhex_s("shr 1 = ", c);
	bn_shr(c, b);
	bn_printhex_s("shrCp = ", b);
	bn_printhex_s("orig  = ", c);

	printf("-- clear and subtract --\n");
	bn_clear(a); bn_clear(b);
	a[1] = 0x42;
	a[0] = 0xFFEAFFEE;
	b[1] = 0x03;
	b[0] = 0xDDAEAFEA;
	bn_sub(a, b, c);
	bn_printhex_s("a     = ", a);
	bn_printhex_s("b     = ", b);
	bn_printhex_s("a - b = ", c);

	bn_clear(a); bn_clear(b);
	a[1] = 1;
	b[1] = 2;
	bn_sub(a, b, c);
	bn_printhex_s("a     = ", a);
	bn_printhex_s("b     = ", b);
	bn_printhex_s("a - b = ", c);

	return 0;
}
