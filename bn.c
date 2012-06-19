/**
 * @file
 * @brief Big number math functions
 * @author Philip Pemberton <philpem@philpem.me.uk>
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>

/// The desired size of a BIGNUM, in bits. Must be a multiple of (sizeof(BN_BASE)/8) bits.
#define BN_BITS 64

/// The BIGNUM element type used for storage of bignums
typedef uint16_t BN_BASE;
/// Used for internal calculation (needs to be at least 1 bit longer than a BN_BASE)
typedef uint32_t BN_EXT;
/// Used for internal calculation where a sign bit is involved
typedef int32_t BN_EXT_SIGNED;

/// Number of BN_BASE elements required to store BN_BITS bits
#define BN_SZ (BN_BITS/8/sizeof(BN_BASE))
/// Maximum value of a single BN_BASE element
#define BN_BASE_MAX ((BN_BASE)-1)

/// Big number type
typedef BN_BASE BIGNUM[BN_SZ];
/// Pointer to a big number
typedef BN_BASE *BIGNUM_P;

/// Define to raise an error in situations where a negative result is generated.
#undef BN_TRAP_NEGATIVE

typedef enum {
	BN_OK				= 0,		///< All systems go!
	BN_E_OVERFLOW,					///< Integer overflow
	BN_E_NEGATIVE					///< Subtraction caused a negative result
} BN_ERR;


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
BN_ERR bn_add(const BIGNUM_P a, const BIGNUM_P b, BIGNUM_P out)
{
	size_t i;
	BN_EXT m = 0;

	for (i=0; i<BN_SZ; i++) {
		m += ((BN_EXT)a[i] + (BN_EXT)b[i]);
		out[i] = m & BN_BASE_MAX;
		m >>= (sizeof(a[0])*8);
	}

	// detect a stray carry (overflow)
	if (m != 0) {
		return BN_E_OVERFLOW;
	} else {
		return BN_OK;
	}
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
BN_ERR bn_sub(const BIGNUM_P a, const BIGNUM_P b, BIGNUM_P out)
{
	size_t i;
	BN_EXT_SIGNED m = 0;

	for (i=0; i<BN_SZ; i++) {
		m = ((BN_EXT_SIGNED)a[i] - (BN_EXT_SIGNED)b[i]) + m;
		out[i] = m & BN_BASE_MAX;
		m >>= (sizeof(a[0])*8);
	}

#ifdef BN_TRAP_NEGATIVE
	if (m != 0) {
		return BN_E_NEGATIVE;
	} else {
		return BN_OK;
	}
#else
	return BN_OK;
#endif
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
BN_ERR bn_copy(const BIGNUM_P a, BIGNUM_P out)
{
	memcpy(out, a, BN_SZ*sizeof(out[0]));
	return BN_OK;
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
BN_ERR bn_clear(BIGNUM_P out)
{
	memset(out, 0, BN_SZ*sizeof(out[0]));
	return BN_OK;
}

// bn_load_int -- Load a longint into a bignum
// bn_load_str -- load a binary stream into a bignum
// bn_save_str -- save a bignum as a binary stream

/**
 * Print a BIGNUM in hexadecimal form.
 *
 * @param a Number to print
 */
BN_ERR bn_printhex(const BIGNUM_P a)
{
	ssize_t i;
	for (i=BN_SZ-1; i>=0; i--) {
		printf("%0*X", (int)(sizeof(BN_BASE)*2), a[i]);
		if (i != 0) putchar('_');
	}

	return BN_OK;
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
BN_ERR bn_printhex_s(const char *s, const BIGNUM_P a)
{
	BN_ERR x;

	printf("%s", s);

	x = bn_printhex(a);
	if (x != BN_OK)
		return x;

	printf("\n");

	return BN_OK;
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
BN_ERR bn_shl(const BIGNUM_P a, BIGNUM_P out)
{
	size_t i;
	BN_EXT m = 0;

	if (a != out) {
		bn_copy(a, out);
	}

	for (i=0; i<BN_SZ; i++) {
		m += (BN_EXT)a[i] << 1;
		out[i] = m & BN_BASE_MAX;
		m >>= (sizeof(a[0]) * 8);
	}

	return BN_OK;
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
BN_ERR bn_shr(const BIGNUM_P a, BIGNUM_P out)
{
	ssize_t i;
	BN_EXT m = 0, tmp;

	if (a != out) {
		bn_copy(a, out);
	}

	for (i=BN_SZ-1; i>=0; i--) {
		tmp = a[i];
		out[i] = m + (a[i] >> 1);
		m = (tmp & 1) << ((sizeof(a[0]) * 8)-1);
	}

	return BN_OK;
}


int main(void)
{
	BIGNUM a, b, c;

	printf("Native int size: %zu\n", sizeof(int));
	printf("Optimal settings:\ntypedef BN_BASE uint%zu_t;\ntypedef BN_EXT uint%zu_t;\ntypedef BN_EXT_SIGNED int%zu_t;\n",
			sizeof(int)*8/2, sizeof(int)*8, sizeof(int)*8);

	printf("sz uint %zu, ui16_t %zu, ui32_t %zu, ui64_t %zu\n", 
			sizeof(unsigned int),
			sizeof(uint16_t),
			sizeof(uint32_t),
			sizeof(uint64_t)
		  );
	printf("BN_SZ = %zu\n", BN_SZ);
	assert(BN_SZ > 0);

	printf("-- clear and add --\n");
	bn_clear(a); bn_clear(b);
	a[0] = b[0] = 0xFFFFFFFFul;
//	b[0] = 0x12345678;
	bn_add(a, b, c);
	bn_printhex_s("a   = ", a);
	bn_printhex_s("b   = ", b);
	bn_printhex_s("a+b = ", c);

	printf("-- shift left --\n");
	bn_clear(c);
	c[0] = 0x40000000ul;
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
	a[0] = 0xFFEAFFEEul;
	b[1] = 0x03;
	b[0] = 0xDDAEAFEAul;
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
