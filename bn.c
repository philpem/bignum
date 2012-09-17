/**
 * @file
 * @brief Big number math functions
 * @author Philip Pemberton <philpem@philpem.me.uk>
 *
 * Most of the algorithms in this file are derived from explanations on
 * Wikipedia. (binary division, long multiplication etc.) or common sense.
 * There are probably bugs here, and the code is almost certainly not
 * optimal.
 *
 * Please send bug reports to philpem@philpem.me.uk.
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>

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
/// Number of bits in a BN_BASE element
#define BN_BASE_BITS ((sizeof(BN_BASE))*8)

/// Big number type
typedef BN_BASE BIGNUM[BN_SZ];
/// Pointer to a big number
typedef BN_BASE *BIGNUM_P;

/// Define to raise an error in situations where a negative result is generated.
#undef BN_TRAP_NEGATIVE

typedef enum {
	BN_OK				= 0,		///< All systems go!
	BN_E_OVERFLOW,					///< Integer overflow
	BN_E_NEGATIVE,					///< Subtraction caused a negative result
	BN_E_DIVIDE_BY_ZERO				///< Attempt to divide by zero
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

/**
 * Return the state of a bit in a BIGNUM.
 *
 * Returns the state (1 or 0) of bit <i>bit</i> in the BIGNUM <i>a</i>.
 *
 * Operation: <i>return_value</i> = (<i>a</i> & (1 << <i>num</i>)) ? 1 : 0;
 *
 * @param a BIGNUM input
 * @param bit Bit number to return, 0 is the least significant bit.
 */
int bn_get_bit(const BIGNUM_P a, int bit)
{
	unsigned int nelem, mask;

	// Calculate element and bit offsets
	nelem = bit / BN_BASE_BITS;
	mask = (1 << (bit % BN_BASE_BITS));

	// TODO: assert if nelem is out of range!

	// Get and return the bit's state
	return (a[nelem] & mask) ? 1 : 0;
}

/**
 * Modify the state of a bit in a BIGNUM.
 *
 * Sets the state (1 or 0) of bit <i>bit</i> in the BIGNUM <i>a</i> to <i>val</i>.
 *
 * Operation: <i>val == 0</i>: <i>a</i> = <i>a</i> & (~(1 << <i>num</i>));
 *            <i>val == 1</i>: <i>a</i> = <i>a</i> | (1 << <i>num</i>);
 *
 * @param a BIGNUM input
 * @param bit Bit number to modify, 0 is the least significant bit.
 * @param val Bit value, 1 or 0
 */
BN_ERR bn_set_bit(BIGNUM_P a, int bit, int val)
{
	unsigned int nelem, mask;

	// Calculate element and bit offsets
	nelem = bit / BN_BASE_BITS;
	mask = (1 << (bit % BN_BASE_BITS));

	// TODO: assert if nelem is out of range!

	// Set the bit's state
	if (val) {
		a[nelem] |= mask;
	} else {
		a[nelem] &= ~mask;
	}

	return BN_OK;
}

/**
 * Check if a BIGNUM is zero.
 *
 * @param a BIGNUM to compare with zero.
 * @return <b>true</b> if <i>a</i> is zero, otherwise <b>false</b>.
 */
bool bn_iszero(const BIGNUM_P a)
{
	ssize_t i;

	for (i=BN_SZ-1; i>=0; i--)
		if (a[i] != 0)
			return false;

	return true;
}

/**
 * Compare two BIGNUMs.
 *
 * @param a First BIGNUM
 * @param b Second BIGNUM
 * @return <b>-1</b> if <i>a</i> < <i>b</i>, <b>0</b> if <i>a</i> == <i>b</i>, or <b>1</b> if <i>a</i> > <i>b</i>.
 */
int bn_cmp(const BIGNUM_P a, const BIGNUM_P b)
{
	ssize_t i;

	for (i=BN_SZ-1; i>=0; i--) {
		if (a[i] < b[i])
			return -1;
		else if (a[i] > b[i])
			return 1;
	}

	return 0;
}

/**
 * Multiply two BIGNUMs.
 *
 * Multiplies <i>a</i> and <i>b</i>, storing the result in <i>out</i>.
 *
 * Operation: <i>out</i> = <i>a</i> * <i>b</i>
 *
 * @param a Multiplier
 * @param b Multiplicand
 * @param out Result
 * @returns BN_OK on success, otherwise a BN_ERR error code.
 */
BN_ERR bn_mul(const BIGNUM_P a, const BIGNUM_P b, BIGNUM_P out)
{
	BIGNUM a_l, b_l;
	BN_ERR err;

	if ((err = bn_copy(a, a_l)) != BN_OK)
		return err;
	if ((err = bn_copy(b, b_l)) != BN_OK)
		return err;
	if ((err = bn_clear(out)) != BN_OK)
		return err;

	while (!bn_iszero(a_l)) {
		if (bn_get_bit(a_l, 0)) {
			if ((err = bn_add(out, b_l, out)) != BN_OK)
				return err;
		}
		if ((err = bn_shr(a_l, a_l)) != BN_OK)
			return err;
		if ((err = bn_shl(b_l, b_l)) != BN_OK)
			return err;
	}

	return BN_OK;
}

/**
 * Divide one BIGNUM by another.
 *
 * Divides <i>n</i> by <i>d</i>, returning the quotient in <i>q</i> and the remainder in <i>r</i>.
 *
 * Operation: <i>q</i> = <i>n</i> / <i>d</i>; <i>r</i> = <i>n</i> % <i>d</i>
 *
 * @param n Numerator
 * @param d Divisor
 * @param q Quotient
 * @param r Remainder
 *
 * @returns BN_OK on success, otherwise a BN_ERR error code.
 *
 * @note Either <i>q</i> or <i>r</i> may be NULL. Thus, this function can
 *       serve double duty as a <i>divide</i> or <i>modulus</i> function, or
 *       perform both operations at the same time.
 */
BN_ERR bn_div(const BIGNUM_P n, const BIGNUM_P d, BIGNUM_P q, BIGNUM_P r)
{
	BIGNUM r_l;
	BN_ERR err;
	ssize_t i;

	// Check for divide-by-zero
	if (bn_iszero(d))
		return BN_E_DIVIDE_BY_ZERO;

	// Initialise quotient and remainder to zero
	if (q != NULL)
		if ((err = bn_clear(q)) != BN_OK)
			return err;
	if ((err = bn_clear(r_l)) != BN_OK)
		return err;

	for (i=BN_BITS-1; i>=0; i--) {
		// Shift remainder left one bit
		if ((err = bn_shl(r_l, r_l)) != BN_OK) return err;
		// Set LSB of R equal to bit I of the numerator
		bn_set_bit(r_l, 0, bn_get_bit(n, i));

		if (bn_cmp(r_l, d) >= 0) {	// if (r >= d)
			bn_sub(r_l, d, r_l);	// r = r - d
			if (q != NULL)				// allow quotient output to be omitted
				bn_set_bit(q, i, 1);	// q.bits[i] = 1
		}
	}

	if (r != NULL)
		bn_copy(r_l, r);
	return BN_OK;
}

BN_ERR bn_load_int(const uint64_t i, BIGNUM_P out)
{
	uint64_t x = i;
	size_t pos = 0;

	bn_clear(out);

	while (x > 0) {
		// Store and shift
		out[pos++] = x & BN_BASE_MAX;
		x >>= BN_BASE_BITS;

		// Avoid buffer overruns
		if (pos >= BN_SZ)
			return BN_E_OVERFLOW;
	}

	return BN_OK;
}

BN_ERR bn_powmod(const BIGNUM_P base, const BIGNUM_P exponent, const BIGNUM_P modulus, BIGNUM_P result)
{
	BN_ERR err;
	BIGNUM base_l, exponent_l, tmp;

	if ((err = bn_load_int(1, result)) != BN_OK)
		return err;
	if ((err = bn_copy(base, base_l)) != BN_OK)
		return err;
	if ((err = bn_copy(exponent, exponent_l)) != BN_OK)
		return err;

	while (!bn_iszero(exponent_l)) {
		// If LSBit of exponent is set...
		if (bn_get_bit(exponent_l, 0)) {
			// result := (result * base) mod modulus
			if ((err = bn_mul(result, base_l, tmp)) != BN_OK)
				return err;
			if ((err = bn_div(tmp, modulus, NULL, result)) != BN_OK)
				return err;
		}
		if ((err = bn_shr(exponent_l, exponent_l)) != BN_OK)
			return err;

		// base = (base * base) mod modulus
		if ((err = bn_mul(base_l, base_l, tmp)) != BN_OK)
			return err;
		if ((err = bn_div(tmp, modulus, NULL, base_l)) != BN_OK)
			return err;
	}

	return BN_OK;
}

// TODO: bn_load_arr -- load a binary array into a bignum
// TODO: bn_save_arr -- save a bignum as a binary array

int main(void)
{
	BIGNUM a, b, c, d;

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

	printf("\n-- clear and add --\n");
	bn_clear(a); bn_clear(b);
	bn_load_int(0xFFFFFFFFul, a);
	bn_load_int(0xFFFFFFFFul, b);
//	b[0] = 0x12345678;
	bn_add(a, b, c);
	bn_printhex_s("a   = ", a);
	bn_printhex_s("b   = ", b);
	bn_printhex_s("a+b = ", c);

	printf("\n-- shift left --\n");
	bn_clear(c);
	bn_load_int(0x40000000ul, c);
	bn_printhex_s("c     = ", c);
	bn_shl(c, c);
	bn_printhex_s("shl 1 = ", c);
	bn_shl(c, b);
	bn_printhex_s("shlCp = ", b);
	bn_printhex_s("orig  = ", c);

	printf("\n-- clear and shr --\n");
	bn_clear(c);
	c[1] = 0x1;
	bn_printhex_s("c     = ", c);
	bn_shr(c, c);
	bn_printhex_s("shr 1 = ", c);
	bn_shr(c, b);
	bn_printhex_s("shrCp = ", b);
	bn_printhex_s("orig  = ", c);

	printf("\n-- clear and subtract --\n");
	bn_clear(a); bn_clear(b);
	bn_load_int(0x42FFEAFFEEull, a);
	bn_load_int(0x03DDAEAFEAull, b);
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

	printf("\n-- multiply (also tests shl, shr, bit_get) --\n");
	bn_clear(a); bn_clear(b);
	a[0] = 0xfeed;
	b[0] = 0xbeef;
	bn_mul(a, b, c);
	bn_printhex_s("a     = ", a);
	bn_printhex_s("b     = ", b);
	bn_printhex_s("a * b = ", c);

	printf("\n-- compare --\n");
	bn_clear(a); bn_clear(b);
	a[1] = 1; a[0] = 0xfeed;
	b[1] = 1; b[0] = 0xbeef;
	bn_printhex_s("a         = ", a);
	bn_printhex_s("b         = ", b);
	       printf("cmp(a, a) = %d\n", bn_cmp(a,a));
	       printf("cmp(a, b) = %d\n", bn_cmp(a,b));
	       printf("cmp(b, a) = %d\n", bn_cmp(b,a));
	       printf("cmp(b, b) = %d\n", bn_cmp(b,b));

	printf("\n-- divide (also tests iszero, clear, shl, get_bit, set_bit, cmp, sub) --\n");
	bn_clear(a); bn_clear(b);
	a[0] = 0xfeed;
	b[0] = 0xbeef;
	bn_div(a, b, c, d);
	bn_printhex_s("a     = ", a);
	bn_printhex_s("b     = ", b);
	bn_printhex_s("a / b = ", c);
	bn_printhex_s("a \% b = ", d);

	printf("\n-- load int --\n");
	bn_load_int(0xFEEDFACEul, a);
	bn_printhex_s("a     = ", a);

	printf("\n-- powmod --\n");
	bn_load_int(4, a);
	bn_load_int(13, b);
	bn_load_int(497, c);
	bn_powmod(a, b, c, d);
	bn_printhex_s("base     = ", a);
	bn_printhex_s("exponent = ", b);
	bn_printhex_s("modulus  = ", c);
	bn_printhex_s("result   = ", d);

	return 0;
}
