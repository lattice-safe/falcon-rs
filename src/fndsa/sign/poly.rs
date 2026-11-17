#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use super::flr::FLR;

// ========================================================================
// Floating-point polynomials
// ========================================================================

// We consider here polynomials in R[X]/(X^n+1), for n a power of two
// between 4 and 1024. We express n = 2^logn for logn in [2, 10]. For
// each such polynomial:
//
//   - The "normal representation" of f = \sum_{i=0}^{n-1} f_i*X^i is
//     the sequence (f_0, f_1, f_2, ... f_{n-1}) as a slice of size n.
//     Elements are FLR instances.
//
//   - The "FFT representation" consists of n/2 complex numbers; the
//     first n/2 elements are the real parts, and for i = 0 to n/2-1,
//     the element i+n/2 in the slice contains the imaginary part
//     corresponding to element i in the slice. Only n/2 complex numbers
//     are needed for the FFT representation because all polynomials
//     are real (in normal representation), making the FFT representation
//     redundant.
//
//   - If a polynomial is self-adjoint then its FFT representation itself
//     contains only real numbers, and the corresponding slice only
//     has n/2 elements; the remaining n/2 (the imaginary parts of the
//     FFT coefficients) are implicitly zero and are omitted.

// Complex multiplication.
#[allow(dead_code)]
#[inline(always)]
pub(crate) fn flc_mul(x_re: FLR, x_im: FLR, y_re: FLR, y_im: FLR) -> (FLR, FLR) {
    (x_re * y_re - x_im * y_im, x_re * y_im + x_im * y_re)
}

/* unused
// Complex division.
#[inline(always)]
fn flc_div(x_re: FLR, x_im: FLR, y_re: FLR, y_im: FLR) -> (FLR, FLR) {
    let m = FLR::ONE / (y_re.square() + y_im.square());
    let b_re = m * y_re;
    let b_im = m * -y_im;
    flc_mul(x_re, x_im, b_re, b_im)
}
*/

// Convert a polynomial from normal representation to FFT.
pub(crate) fn FFT(logn: u32, f: &mut [FLR]) {
    // First iteration of the FFT algorithm would compute
    // f[j] + i*f[j + n/2] for all j < n/2; since this is exactly our
    // storage format for complex numbers in the FFT representation,
    // that first iteration is a no-op, hence we can start the computation
    // at the second iteration.

    {
        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut t = hn;
        for lm in 1..logn {
            let m = 1 << lm;
            let hm = m >> 1;
            let ht = t >> 1;
            let mut j0 = 0;
            for i in 0..hm {
                let s_re = GM[((m + i) << 1) + 0];
                let s_im = GM[((m + i) << 1) + 1];
                for j in 0..ht {
                    let j1 = j0 + j;
                    let j2 = j1 + ht;
                    let x_re = f[j1];
                    let x_im = f[j1 + hn];
                    let y_re = f[j2];
                    let y_im = f[j2 + hn];
                    let (z_re, z_im) = flc_mul(y_re, y_im, s_re, s_im);
                    f[j1] = x_re + z_re;
                    f[j1 + hn] = x_im + z_im;
                    f[j2] = x_re - z_re;
                    f[j2 + hn] = x_im - z_im;
                }
                j0 += t;
            }
            t = ht;
        }
    }
}

// Convert a polynomial from FFT representation to normal.
pub(crate) fn iFFT(logn: u32, f: &mut [FLR]) {
    // This is the reverse of FFT. We use the fact that if
    // w = exp(i*k*pi/N), then 1/w is the conjugate of w; thus, we can
    // get inverses from the table GM[] itself by simply negating the
    // imaginary part.
    //
    // The last iteration is a no-op (like the first iteration in FFT).
    // Since the last iteration is skipped, we have to perform only
    // a division by n/2 at the end.

    {
        assert!(logn >= 1);
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut t = 1;
        for lm in 1..logn {
            let hm = 1 << (logn - lm);
            let dt = t << 1;
            let mut j0 = 0;
            for i in 0..(hm >> 1) {
                let s_re = GM[((hm + i) << 1) + 0];
                let s_im = -GM[((hm + i) << 1) + 1];
                for j in 0..t {
                    let j1 = j0 + j;
                    let j2 = j1 + t;
                    let x_re = f[j1];
                    let x_im = f[j1 + hn];
                    let y_re = f[j2];
                    let y_im = f[j2 + hn];
                    f[j1] = x_re + y_re;
                    f[j1 + hn] = x_im + y_im;
                    let x_re = x_re - y_re;
                    let x_im = x_im - y_im;
                    let (z_re, z_im) = flc_mul(x_re, x_im, s_re, s_im);
                    f[j2] = z_re;
                    f[j2 + hn] = z_im;
                }
                j0 += dt;
            }
            t = dt;
        }

        // We have logn-1 delayed halvings to perform, i.e. we must divide
        // all returned values by n/2.
        FLR::slice_div2e(&mut f[..n], logn - 1);
    }
}

// Set polynomial d from polynomial f with small coefficients.
pub(crate) fn poly_set_small(logn: u32, d: &mut [FLR], f: &[i8]) {
    {
        for i in 0..(1usize << logn) {
            d[i] = FLR::from_i32(f[i] as i32);
        }
    }
}

// Add polynomial b to polynomial a.
pub(crate) fn poly_add(logn: u32, a: &mut [FLR], b: &[FLR]) {
    {
        for i in 0..(1usize << logn) {
            a[i] += b[i];
        }
    }
}

// Subtract polynomial b from polynomial a.
pub(crate) fn poly_sub(logn: u32, a: &mut [FLR], b: &[FLR]) {
    {
        for i in 0..(1usize << logn) {
            a[i] -= b[i];
        }
    }
}

// Negate polynomial a.
pub(crate) fn poly_neg(logn: u32, a: &mut [FLR]) {
    {
        for i in 0..(1usize << logn) {
            a[i] = -a[i];
        }
    }
}

/* unused
// Replace polynomial a with its Hermitian adjoint adj(a). The polynomial
// must be in FFT representation.
pub(crate) fn poly_adj_fft(logn: u32, a: &mut [FLR]) {
    let n = 1usize << logn;
    for i in (n >> 1)..n {
        a[i] = -a[i];
    }
}
*/

// Multiply polynomial a with polynomial b. The polynomials must be in
// FFT representation.
pub(crate) fn poly_mul_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}

// Multiply polynomial a with the adjoint of polynomial b. The polynomials
// must be in FFT representation.
pub(crate) fn poly_muladj_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            let (re, im) = flc_mul(a[i], a[i + hn], b[i], -b[i + hn]);
            a[i] = re;
            a[i + hn] = im;
        }
    }
}

// Multiply polynomial a with its own adjoint. The polynomial must be in
// FFT representation. Since the result is a self-adjoint polynomial,
// coefficients n/2 to n-1 are set to zero.
pub(crate) fn poly_mulownadj_fft(logn: u32, a: &mut [FLR]) {
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            a[i] = a[i].square() + a[i + hn].square();
            a[i + hn] = FLR::ZERO;
        }
    }
}

// Multiply polynomial a with a real constant x.
pub(crate) fn poly_mulconst(logn: u32, a: &mut [FLR], x: FLR) {
    {
        for i in 0..(1usize << logn) {
            a[i] *= x;
        }
    }
}

/* unused
// Divide polynomial a by polynomial b. The polynomials MUST be in FFT
// representation.
pub(crate) fn poly_div_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let (re, im) = flc_div(a[i], a[i + hn], b[i], b[i + hn]);
        a[i] = re;
        a[i + hn] = im;
    }
}
*/

/* unused
// Set polynomial d to 1/(f*adj(f) + g*adj(g)). All polynomials are in
// FFT representation. Since the output d is self-adjoint, only its
// first n/2 coefficients are set; the other n/2 coefficients are
// implicitly zero, but need not exist in the destination slice.
pub(crate) fn poly_invnorm2_fft(logn: u32,
    d: &mut [FLR], f: &[FLR], g: &[FLR])
{
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let nf = f[i].square() + f[i + hn].square();
        let ng = g[i].square() + g[i + hn].square();
        d[i] = FLR::ONE / (nf + ng);
    }
}
*/

/* unused
// Given polynomial F, G, f and g, set d to F*adj(f) + G*adj(g). All
// polynomials are in FFT representation.
pub(crate) fn poly_add_muladj_fft(logn: u32,
    d: &mut [FLR], F: &[FLR], G: &[FLR], f: &[FLR], g: &[FLR])
{
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let (a_re, a_im) = flc_mul(F[i], F[i + hn], f[i], f[i + hn]);
        let (b_re, b_im) = flc_mul(G[i], G[i + hn], g[i], g[i + hn]);
        d[i] = a_re + b_re;
        d[i + hn] = a_im + b_im;
    }
}
*/

/* unused
// Multiply polynomial a by polynomial b, where b is self-adjoint. Only
// the first n/2 coefficients of b are accessed. All polynomials are in
// FFT representation.
pub(crate) fn poly_mul_selfadj_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        a[i] *= b[i];
        a[i + hn] *= b[i];
    }
}
*/

/* unused
// Divide polynomial a by polynomial b, where b is self-adjoint. Only
// the first n/2 coefficients of b are accessed. All polynomials are in
// FFT representation.
pub(crate) fn poly_div_selfadj_fft(logn: u32, a: &mut [FLR], b: &[FLR]) {
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let x = FLR::ONE / b[i];
        a[i] *= x;
        a[i + hn] *= x;
    }
}
*/

// Perform an LDL decomposition of a self-adjoint matrix G. The matrix
// is G = [[g00, g01], [adj(g01), g11]]; g00 and g11 are self-adjoint
// polynomials. The decomposition is G = L*D*adj(L), with:
//    D = [[g00, 0], [0, d11]]
//    L = [[1, 0], [l10, 1]]
// The output polynomials l10 and d11 are written over g01 and g11,
// respectively. Like g11, d11 is self-adjoint and uses only n/2
// coefficients. g00 is unmodified. All polynomials are in FFT
// representation.
pub(crate) fn poly_LDL_fft(logn: u32, g00: &[FLR], g01: &mut [FLR], g11: &mut [FLR]) {
    {
        let hn = 1usize << (logn - 1);
        for i in 0..hn {
            // g00 and g11 are self-adjoint
            let g00_re = g00[i];
            let (g01_re, g01_im) = (g01[i], g01[i + hn]);
            let g11_re = g11[i];
            let inv_g00_re = FLR::ONE / g00_re;
            let (mu_re, mu_im) = (g01_re * inv_g00_re, g01_im * inv_g00_re);
            let zo_re = mu_re * g01_re + mu_im * g01_im;
            g11[i] = g11_re - zo_re;
            g01[i] = mu_re;
            g01[i + hn] = -mu_im;
        }
    }
}

/* unused
// This is identical to poly_LDL_fft() except that the output polynomials
// l10 and d11 are written into separate output buffers instead of
// overwriting the provided g01 and g11.
pub(crate) fn poly_LDLmv_fft(logn: u32,
    d11: &mut [FLR], l10: &mut [FLR], g00: &[FLR], g01: &[FLR], g11: &[FLR])
{
    let hn = 1usize << (logn - 1);
    for i in 0..hn {
        let (g00_re, g00_im) = (g00[i], g00[i + hn]);
        let (g01_re, g01_im) = (g01[i], g01[i + hn]);
        let (g11_re, g11_im) = (g11[i], g11[i + hn]);
        let (mu_re, mu_im) = flc_div(g01_re, g01_im, g00_re, g00_im);
        let (zo_re, zo_im) = flc_mul(mu_re, mu_im, g01_re, -g01_im);
        d11[i] = g11_re - zo_re;
        d11[i + hn] = g11_im - zo_im;
        l10[i] = mu_re;
        l10[i + hn] = -mu_im;
    }
}
*/

// Split operation on a polynomial: for input polynomial f, half-size
// polynomials f0 and f1 (modulo X^(n/2)+1) are such that
// f = f0(x^2) + x*f1(x^2). All polynomials are in FFT representation.
pub(crate) fn poly_split_fft(logn: u32, f0: &mut [FLR], f1: &mut [FLR], f: &[FLR]) {
    // Only called from the sampler's recursion, where logn >= 2 (the
    // logn = 1 leaf is handled there directly); upstream's logn = 1
    // special case is therefore unreachable here.
    debug_assert!(logn >= 2);

    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        for i in 0..qn {
            let (a_re, a_im) = (f[(i << 1) + 0], f[(i << 1) + 0 + hn]);
            let (b_re, b_im) = (f[(i << 1) + 1], f[(i << 1) + 1 + hn]);

            let (t_re, t_im) = (a_re + b_re, a_im + b_im);
            f0[i] = t_re.half();
            f0[i + qn] = t_im.half();

            let (t_re, t_im) = (a_re - b_re, a_im - b_im);
            let (u_re, u_im) = flc_mul(
                t_re,
                t_im,
                GM[((i + hn) << 1) + 0],
                -GM[((i + hn) << 1) + 1],
            );
            f1[i] = u_re.half();
            f1[i + qn] = u_im.half();
        }
    }
}

// Specialized version of poly_split_fft() when the source polynomial
// is self-adjoint (i.e. all its FFT coefficients are real). On output,
// f0 is self-adjoint, but f1 is not necessarily self-adjoint.
pub(crate) fn poly_split_selfadj_fft(logn: u32, f0: &mut [FLR], f1: &mut [FLR], f: &[FLR]) {
    // Only called from the sampler's recursion, where logn >= 2 (the
    // logn = 1 leaf is handled there directly); upstream's logn = 1
    // special case is therefore unreachable here.
    debug_assert!(logn >= 2);

    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        for i in 0..qn {
            let a_re = f[(i << 1) + 0];
            let b_re = f[(i << 1) + 1];

            let t_re = a_re + b_re;
            f0[i] = t_re.half();
            f0[i + qn] = FLR::ZERO;

            let t_re = (a_re - b_re).half();
            f1[i] = t_re * GM[((i + hn) << 1) + 0];
            f1[i + qn] = t_re * -GM[((i + hn) << 1) + 1];
        }
    }
}

// Merge operation on a polynomial: for input half-size polynomials f0
// and f1 (modulo X^(n/2)+1), compute f = f0(x^2) + x*f1(x^2). All
// polynomials are in FFT representation.
pub(crate) fn poly_merge_fft(logn: u32, f: &mut [FLR], f0: &[FLR], f1: &[FLR]) {
    // Only called from the sampler's recursion, where logn >= 2 (the
    // logn = 1 leaf is handled there directly); upstream's logn = 1
    // special case is therefore unreachable here.
    debug_assert!(logn >= 2);

    {
        let hn = 1usize << (logn - 1);
        let qn = hn >> 1;
        for i in 0..qn {
            let (a_re, a_im) = (f0[i], f0[i + qn]);
            let (b_re, b_im) = flc_mul(
                f1[i],
                f1[i + qn],
                GM[((i + hn) << 1) + 0],
                GM[((i + hn) << 1) + 1],
            );
            f[(i << 1) + 0] = a_re + b_re;
            f[(i << 1) + 0 + hn] = a_im + b_im;
            f[(i << 1) + 1] = a_re - b_re;
            f[(i << 1) + 1 + hn] = a_im - b_im;
        }
    }
}

// Table of constants for FFT. For k = 1 to 1023, define j = rev10(k), with
// rev10() being the bit-reversal function over 10 bits. Then:
//   GM[2*k + 0] = cos(j*pi/1024)
//   GM[2*k + 1] = sin(j*pi/1024)
// Here, all values are computed from integer approximations which were
// obtained from Sage, which employs sufficient precision to get an exact
// rounding. Specifically, we round x = cos(j*pi/1024) by looking for the
// integer n such that abs(x)*2^n is in [2^52, 2^53[, and make the value
// as round(x*2^n)/2^n (with FLR::scaled()).
// A test makes sure that the generated FLR constants have exactly the
// expected values.
//
// GM[0] and GM[1] (corresponding to k = 0) are unused and left to zero.

pub(crate) const GM: [FLR; 2048] = [
    FLR::ZERO,
    FLR::ZERO,
    FLR::NZERO,
    FLR::ONE,
    FLR::scaled(6369051672525773, -53),
    FLR::scaled(6369051672525773, -53),
    FLR::scaled(-6369051672525773, -53),
    FLR::scaled(6369051672525773, -53),
    FLR::scaled(8321567036706118, -53),
    FLR::scaled(6893811853601123, -54),
    FLR::scaled(-6893811853601123, -54),
    FLR::scaled(8321567036706118, -53),
    FLR::scaled(6893811853601123, -54),
    FLR::scaled(8321567036706118, -53),
    FLR::scaled(-8321567036706118, -53),
    FLR::scaled(6893811853601123, -54),
    FLR::scaled(8834128446708912, -53),
    FLR::scaled(7028869612283403, -55),
    FLR::scaled(-7028869612283403, -55),
    FLR::scaled(8834128446708912, -53),
    FLR::scaled(5004131788810440, -53),
    FLR::scaled(7489212472271267, -53),
    FLR::scaled(-7489212472271267, -53),
    FLR::scaled(5004131788810440, -53),
    FLR::scaled(7489212472271267, -53),
    FLR::scaled(5004131788810440, -53),
    FLR::scaled(-5004131788810440, -53),
    FLR::scaled(7489212472271267, -53),
    FLR::scaled(7028869612283403, -55),
    FLR::scaled(8834128446708912, -53),
    FLR::scaled(-8834128446708912, -53),
    FLR::scaled(7028869612283403, -55),
    FLR::scaled(8963827128411430, -53),
    FLR::scaled(7062879306626092, -56),
    FLR::scaled(-7062879306626092, -56),
    FLR::scaled(8963827128411430, -53),
    FLR::scaled(5714106716331478, -53),
    FLR::scaled(6962659179435841, -53),
    FLR::scaled(-6962659179435841, -53),
    FLR::scaled(5714106716331478, -53),
    FLR::scaled(7943640554978737, -53),
    FLR::scaled(8491928673252923, -54),
    FLR::scaled(-8491928673252923, -54),
    FLR::scaled(7943640554978737, -53),
    FLR::scaled(5229303857258246, -54),
    FLR::scaled(8619352278838746, -53),
    FLR::scaled(-8619352278838746, -53),
    FLR::scaled(5229303857258246, -54),
    FLR::scaled(8619352278838746, -53),
    FLR::scaled(5229303857258246, -54),
    FLR::scaled(-5229303857258246, -54),
    FLR::scaled(8619352278838746, -53),
    FLR::scaled(8491928673252923, -54),
    FLR::scaled(7943640554978737, -53),
    FLR::scaled(-7943640554978737, -53),
    FLR::scaled(8491928673252923, -54),
    FLR::scaled(6962659179435841, -53),
    FLR::scaled(5714106716331478, -53),
    FLR::scaled(-5714106716331478, -53),
    FLR::scaled(6962659179435841, -53),
    FLR::scaled(7062879306626092, -56),
    FLR::scaled(8963827128411430, -53),
    FLR::scaled(-8963827128411430, -53),
    FLR::scaled(7062879306626092, -56),
    FLR::scaled(8996349688769918, -53),
    FLR::scaled(7071397114140692, -57),
    FLR::scaled(-7071397114140692, -57),
    FLR::scaled(8996349688769918, -53),
    FLR::scaled(6048865317612704, -53),
    FLR::scaled(6673894424096687, -53),
    FLR::scaled(-6673894424096687, -53),
    FLR::scaled(6048865317612704, -53),
    FLR::scaled(8142411687315315, -53),
    FLR::scaled(7702147837811904, -54),
    FLR::scaled(-7702147837811904, -54),
    FLR::scaled(8142411687315315, -53),
    FLR::scaled(6068868072808413, -54),
    FLR::scaled(8480675002222309, -53),
    FLR::scaled(-8480675002222309, -53),
    FLR::scaled(6068868072808413, -54),
    FLR::scaled(8737264780849367, -53),
    FLR::scaled(8754283581366043, -55),
    FLR::scaled(-8754283581366043, -55),
    FLR::scaled(8737264780849367, -53),
    FLR::scaled(4630625854357486, -53),
    FLR::scaled(7725732496764478, -53),
    FLR::scaled(-7725732496764478, -53),
    FLR::scaled(4630625854357486, -53),
    FLR::scaled(7234650278954817, -53),
    FLR::scaled(5365582331473973, -53),
    FLR::scaled(-5365582331473973, -53),
    FLR::scaled(7234650278954817, -53),
    FLR::scaled(5286522480648506, -55),
    FLR::scaled(8909709923362071, -53),
    FLR::scaled(-8909709923362071, -53),
    FLR::scaled(5286522480648506, -55),
    FLR::scaled(8909709923362071, -53),
    FLR::scaled(5286522480648506, -55),
    FLR::scaled(-5286522480648506, -55),
    FLR::scaled(8909709923362071, -53),
    FLR::scaled(5365582331473973, -53),
    FLR::scaled(7234650278954817, -53),
    FLR::scaled(-7234650278954817, -53),
    FLR::scaled(5365582331473973, -53),
    FLR::scaled(7725732496764478, -53),
    FLR::scaled(4630625854357486, -53),
    FLR::scaled(-4630625854357486, -53),
    FLR::scaled(7725732496764478, -53),
    FLR::scaled(8754283581366043, -55),
    FLR::scaled(8737264780849367, -53),
    FLR::scaled(-8737264780849367, -53),
    FLR::scaled(8754283581366043, -55),
    FLR::scaled(8480675002222309, -53),
    FLR::scaled(6068868072808413, -54),
    FLR::scaled(-6068868072808413, -54),
    FLR::scaled(8480675002222309, -53),
    FLR::scaled(7702147837811904, -54),
    FLR::scaled(8142411687315315, -53),
    FLR::scaled(-8142411687315315, -53),
    FLR::scaled(7702147837811904, -54),
    FLR::scaled(6673894424096687, -53),
    FLR::scaled(6048865317612704, -53),
    FLR::scaled(-6048865317612704, -53),
    FLR::scaled(6673894424096687, -53),
    FLR::scaled(7071397114140692, -57),
    FLR::scaled(8996349688769918, -53),
    FLR::scaled(-8996349688769918, -53),
    FLR::scaled(7071397114140692, -57),
    FLR::scaled(9004486454725901, -53),
    FLR::scaled(7073527528384126, -58),
    FLR::scaled(-7073527528384126, -58),
    FLR::scaled(9004486454725901, -53),
    FLR::scaled(6210829080669407, -53),
    FLR::scaled(6523437785808790, -53),
    FLR::scaled(-6523437785808790, -53),
    FLR::scaled(6210829080669407, -53),
    FLR::scaled(8234469430249786, -53),
    FLR::scaled(7300178522992010, -54),
    FLR::scaled(-7300178522992010, -54),
    FLR::scaled(8234469430249786, -53),
    FLR::scaled(6483292609725855, -54),
    FLR::scaled(8403652042342972, -53),
    FLR::scaled(-8403652042342972, -53),
    FLR::scaled(6483292609725855, -54),
    FLR::scaled(8788343498532233, -53),
    FLR::scaled(7893954108215139, -55),
    FLR::scaled(-7893954108215139, -55),
    FLR::scaled(8788343498532233, -53),
    FLR::scaled(4818830163135267, -53),
    FLR::scaled(7609764403282432, -53),
    FLR::scaled(-7609764403282432, -53),
    FLR::scaled(4818830163135267, -53),
    FLR::scaled(7364149319706498, -53),
    FLR::scaled(5186419112612575, -53),
    FLR::scaled(-5186419112612575, -53),
    FLR::scaled(7364149319706498, -53),
    FLR::scaled(6159551188123590, -55),
    FLR::scaled(8874592046238633, -53),
    FLR::scaled(-8874592046238633, -53),
    FLR::scaled(6159551188123590, -55),
    FLR::scaled(8939460924383187, -53),
    FLR::scaled(8820618739413774, -56),
    FLR::scaled(-8820618739413774, -56),
    FLR::scaled(8939460924383187, -53),
    FLR::scaled(5541513524170937, -53),
    FLR::scaled(7100793355396091, -53),
    FLR::scaled(-7100793355396091, -53),
    FLR::scaled(5541513524170937, -53),
    FLR::scaled(7837046897874218, -53),
    FLR::scaled(8879264459430586, -54),
    FLR::scaled(-8879264459430586, -54),
    FLR::scaled(7837046897874218, -53),
    FLR::scaled(4804669900715639, -54),
    FLR::scaled(8680923061569891, -53),
    FLR::scaled(-8680923061569891, -53),
    FLR::scaled(4804669900715639, -54),
    FLR::scaled(8552589520593170, -53),
    FLR::scaled(5650787876693505, -54),
    FLR::scaled(-5650787876693505, -54),
    FLR::scaled(8552589520593170, -53),
    FLR::scaled(8099477666776158, -54),
    FLR::scaled(8045449260044789, -53),
    FLR::scaled(-8045449260044789, -53),
    FLR::scaled(8099477666776158, -54),
    FLR::scaled(6820330957936494, -53),
    FLR::scaled(5883257944270313, -53),
    FLR::scaled(-5883257944270313, -53),
    FLR::scaled(6820330957936494, -53),
    FLR::scaled(5300885459442166, -56),
    FLR::scaled(8982793858156602, -53),
    FLR::scaled(-8982793858156602, -53),
    FLR::scaled(5300885459442166, -56),
    FLR::scaled(8982793858156602, -53),
    FLR::scaled(5300885459442166, -56),
    FLR::scaled(-5300885459442166, -56),
    FLR::scaled(8982793858156602, -53),
    FLR::scaled(5883257944270313, -53),
    FLR::scaled(6820330957936494, -53),
    FLR::scaled(-6820330957936494, -53),
    FLR::scaled(5883257944270313, -53),
    FLR::scaled(8045449260044789, -53),
    FLR::scaled(8099477666776158, -54),
    FLR::scaled(-8099477666776158, -54),
    FLR::scaled(8045449260044789, -53),
    FLR::scaled(5650787876693505, -54),
    FLR::scaled(8552589520593170, -53),
    FLR::scaled(-8552589520593170, -53),
    FLR::scaled(5650787876693505, -54),
    FLR::scaled(8680923061569891, -53),
    FLR::scaled(4804669900715639, -54),
    FLR::scaled(-4804669900715639, -54),
    FLR::scaled(8680923061569891, -53),
    FLR::scaled(8879264459430586, -54),
    FLR::scaled(7837046897874218, -53),
    FLR::scaled(-7837046897874218, -53),
    FLR::scaled(8879264459430586, -54),
    FLR::scaled(7100793355396091, -53),
    FLR::scaled(5541513524170937, -53),
    FLR::scaled(-5541513524170937, -53),
    FLR::scaled(7100793355396091, -53),
    FLR::scaled(8820618739413774, -56),
    FLR::scaled(8939460924383187, -53),
    FLR::scaled(-8939460924383187, -53),
    FLR::scaled(8820618739413774, -56),
    FLR::scaled(8874592046238633, -53),
    FLR::scaled(6159551188123590, -55),
    FLR::scaled(-6159551188123590, -55),
    FLR::scaled(8874592046238633, -53),
    FLR::scaled(5186419112612575, -53),
    FLR::scaled(7364149319706498, -53),
    FLR::scaled(-7364149319706498, -53),
    FLR::scaled(5186419112612575, -53),
    FLR::scaled(7609764403282432, -53),
    FLR::scaled(4818830163135267, -53),
    FLR::scaled(-4818830163135267, -53),
    FLR::scaled(7609764403282432, -53),
    FLR::scaled(7893954108215139, -55),
    FLR::scaled(8788343498532233, -53),
    FLR::scaled(-8788343498532233, -53),
    FLR::scaled(7893954108215139, -55),
    FLR::scaled(8403652042342972, -53),
    FLR::scaled(6483292609725855, -54),
    FLR::scaled(-6483292609725855, -54),
    FLR::scaled(8403652042342972, -53),
    FLR::scaled(7300178522992010, -54),
    FLR::scaled(8234469430249786, -53),
    FLR::scaled(-8234469430249786, -53),
    FLR::scaled(7300178522992010, -54),
    FLR::scaled(6523437785808790, -53),
    FLR::scaled(6210829080669407, -53),
    FLR::scaled(-6210829080669407, -53),
    FLR::scaled(6523437785808790, -53),
    FLR::scaled(7073527528384126, -58),
    FLR::scaled(9004486454725901, -53),
    FLR::scaled(-9004486454725901, -53),
    FLR::scaled(7073527528384126, -58),
    FLR::scaled(9006521029202651, -53),
    FLR::scaled(7074060192106372, -59),
    FLR::scaled(-7074060192106372, -59),
    FLR::scaled(9006521029202651, -53),
    FLR::scaled(6290414033205309, -53),
    FLR::scaled(6446730156091567, -53),
    FLR::scaled(-6446730156091567, -53),
    FLR::scaled(6290414033205309, -53),
    FLR::scaled(8278641599964811, -53),
    FLR::scaled(7097529619223511, -54),
    FLR::scaled(-7097529619223511, -54),
    FLR::scaled(8278641599964811, -53),
    FLR::scaled(6689055905271015, -54),
    FLR::scaled(8363239276060827, -53),
    FLR::scaled(-8363239276060827, -53),
    FLR::scaled(6689055905271015, -54),
    FLR::scaled(8811899492445997, -53),
    FLR::scaled(7461973733147729, -55),
    FLR::scaled(-7461973733147729, -55),
    FLR::scaled(8811899492445997, -53),
    FLR::scaled(4911850829306697, -53),
    FLR::scaled(7550056943179025, -53),
    FLR::scaled(-7550056943179025, -53),
    FLR::scaled(4911850829306697, -53),
    FLR::scaled(7427240153512674, -53),
    FLR::scaled(5095659144473433, -53),
    FLR::scaled(-5095659144473433, -53),
    FLR::scaled(7427240153512674, -53),
    FLR::scaled(6594706969509681, -55),
    FLR::scaled(8855027013722231, -53),
    FLR::scaled(-8855027013722231, -53),
    FLR::scaled(6594706969509681, -55),
    FLR::scaled(8952318119487099, -53),
    FLR::scaled(7942347067146965, -56),
    FLR::scaled(-7942347067146965, -56),
    FLR::scaled(8952318119487099, -53),
    FLR::scaled(5628233915913940, -53),
    FLR::scaled(7032255783343117, -53),
    FLR::scaled(-7032255783343117, -53),
    FLR::scaled(5628233915913940, -53),
    FLR::scaled(7890937899537737, -53),
    FLR::scaled(8686250625038550, -54),
    FLR::scaled(-8686250625038550, -54),
    FLR::scaled(7890937899537737, -53),
    FLR::scaled(5017364677319486, -54),
    FLR::scaled(8650789058710388, -53),
    FLR::scaled(-8650789058710388, -53),
    FLR::scaled(5017364677319486, -54),
    FLR::scaled(8586617456218381, -53),
    FLR::scaled(5440455523270994, -54),
    FLR::scaled(-5440455523270994, -54),
    FLR::scaled(8586617456218381, -53),
    FLR::scaled(8296327868244873, -54),
    FLR::scaled(7995146927371163, -53),
    FLR::scaled(-7995146927371163, -53),
    FLR::scaled(8296327868244873, -54),
    FLR::scaled(6892014024666815, -53),
    FLR::scaled(5799118993295673, -53),
    FLR::scaled(-5799118993295673, -53),
    FLR::scaled(6892014024666815, -53),
    FLR::scaled(6182347902460953, -56),
    FLR::scaled(8973986217941769, -53),
    FLR::scaled(-8973986217941769, -53),
    FLR::scaled(6182347902460953, -56),
    FLR::scaled(8990248722657709, -53),
    FLR::scaled(8837249445142752, -57),
    FLR::scaled(-8837249445142752, -57),
    FLR::scaled(8990248722657709, -53),
    FLR::scaled(5966510898238870, -53),
    FLR::scaled(6747620774451057, -53),
    FLR::scaled(-6747620774451057, -53),
    FLR::scaled(5966510898238870, -53),
    FLR::scaled(8094539977653340, -53),
    FLR::scaled(7901407713763047, -54),
    FLR::scaled(-7901407713763047, -54),
    FLR::scaled(8094539977653340, -53),
    FLR::scaled(5860269242247018, -54),
    FLR::scaled(8517273596445054, -53),
    FLR::scaled(-8517273596445054, -53),
    FLR::scaled(5860269242247018, -54),
    FLR::scaled(8709749749347266, -53),
    FLR::scaled(4591251558497710, -54),
    FLR::scaled(-4591251558497710, -54),
    FLR::scaled(8709749749347266, -53),
    FLR::scaled(4535470554627767, -53),
    FLR::scaled(7781975665774802, -53),
    FLR::scaled(-7781975665774802, -53),
    FLR::scaled(4535470554627767, -53),
    FLR::scaled(7168261574088514, -53),
    FLR::scaled(5453958600874483, -53),
    FLR::scaled(-5453958600874483, -53),
    FLR::scaled(7168261574088514, -53),
    FLR::scaled(4848781029471607, -55),
    FLR::scaled(8925257479345985, -53),
    FLR::scaled(-8925257479345985, -53),
    FLR::scaled(4848781029471607, -55),
    FLR::scaled(8892820597836187, -53),
    FLR::scaled(5723467800985178, -55),
    FLR::scaled(-5723467800985178, -55),
    FLR::scaled(8892820597836187, -53),
    FLR::scaled(5276398025110506, -53),
    FLR::scaled(7299949472100244, -53),
    FLR::scaled(-7299949472100244, -53),
    FLR::scaled(5276398025110506, -53),
    FLR::scaled(7668325860857618, -53),
    FLR::scaled(4725083798866319, -53),
    FLR::scaled(-4725083798866319, -53),
    FLR::scaled(7668325860857618, -53),
    FLR::scaled(8324745682830097, -55),
    FLR::scaled(8763464012413658, -53),
    FLR::scaled(-8763464012413658, -53),
    FLR::scaled(8324745682830097, -55),
    FLR::scaled(8442799249538603, -53),
    FLR::scaled(6276552954161094, -54),
    FLR::scaled(-6276552954161094, -54),
    FLR::scaled(8442799249538603, -53),
    FLR::scaled(7501728046727114, -54),
    FLR::scaled(8189057179727324, -53),
    FLR::scaled(-8189057179727324, -53),
    FLR::scaled(7501728046727114, -54),
    FLR::scaled(6599163009790561, -53),
    FLR::scaled(6130308800119180, -53),
    FLR::scaled(-6130308800119180, -53),
    FLR::scaled(6599163009790561, -53),
    FLR::scaled(5304479856743885, -57),
    FLR::scaled(9001095837710173, -53),
    FLR::scaled(-9001095837710173, -53),
    FLR::scaled(5304479856743885, -57),
    FLR::scaled(9001095837710173, -53),
    FLR::scaled(5304479856743885, -57),
    FLR::scaled(-5304479856743885, -57),
    FLR::scaled(9001095837710173, -53),
    FLR::scaled(6130308800119180, -53),
    FLR::scaled(6599163009790561, -53),
    FLR::scaled(-6599163009790561, -53),
    FLR::scaled(6130308800119180, -53),
    FLR::scaled(8189057179727324, -53),
    FLR::scaled(7501728046727114, -54),
    FLR::scaled(-7501728046727114, -54),
    FLR::scaled(8189057179727324, -53),
    FLR::scaled(6276552954161094, -54),
    FLR::scaled(8442799249538603, -53),
    FLR::scaled(-8442799249538603, -53),
    FLR::scaled(6276552954161094, -54),
    FLR::scaled(8763464012413658, -53),
    FLR::scaled(8324745682830097, -55),
    FLR::scaled(-8324745682830097, -55),
    FLR::scaled(8763464012413658, -53),
    FLR::scaled(4725083798866319, -53),
    FLR::scaled(7668325860857618, -53),
    FLR::scaled(-7668325860857618, -53),
    FLR::scaled(4725083798866319, -53),
    FLR::scaled(7299949472100244, -53),
    FLR::scaled(5276398025110506, -53),
    FLR::scaled(-5276398025110506, -53),
    FLR::scaled(7299949472100244, -53),
    FLR::scaled(5723467800985178, -55),
    FLR::scaled(8892820597836187, -53),
    FLR::scaled(-8892820597836187, -53),
    FLR::scaled(5723467800985178, -55),
    FLR::scaled(8925257479345985, -53),
    FLR::scaled(4848781029471607, -55),
    FLR::scaled(-4848781029471607, -55),
    FLR::scaled(8925257479345985, -53),
    FLR::scaled(5453958600874483, -53),
    FLR::scaled(7168261574088514, -53),
    FLR::scaled(-7168261574088514, -53),
    FLR::scaled(5453958600874483, -53),
    FLR::scaled(7781975665774802, -53),
    FLR::scaled(4535470554627767, -53),
    FLR::scaled(-4535470554627767, -53),
    FLR::scaled(7781975665774802, -53),
    FLR::scaled(4591251558497710, -54),
    FLR::scaled(8709749749347266, -53),
    FLR::scaled(-8709749749347266, -53),
    FLR::scaled(4591251558497710, -54),
    FLR::scaled(8517273596445054, -53),
    FLR::scaled(5860269242247018, -54),
    FLR::scaled(-5860269242247018, -54),
    FLR::scaled(8517273596445054, -53),
    FLR::scaled(7901407713763047, -54),
    FLR::scaled(8094539977653340, -53),
    FLR::scaled(-8094539977653340, -53),
    FLR::scaled(7901407713763047, -54),
    FLR::scaled(6747620774451057, -53),
    FLR::scaled(5966510898238870, -53),
    FLR::scaled(-5966510898238870, -53),
    FLR::scaled(6747620774451057, -53),
    FLR::scaled(8837249445142752, -57),
    FLR::scaled(8990248722657709, -53),
    FLR::scaled(-8990248722657709, -53),
    FLR::scaled(8837249445142752, -57),
    FLR::scaled(8973986217941769, -53),
    FLR::scaled(6182347902460953, -56),
    FLR::scaled(-6182347902460953, -56),
    FLR::scaled(8973986217941769, -53),
    FLR::scaled(5799118993295673, -53),
    FLR::scaled(6892014024666815, -53),
    FLR::scaled(-6892014024666815, -53),
    FLR::scaled(5799118993295673, -53),
    FLR::scaled(7995146927371163, -53),
    FLR::scaled(8296327868244873, -54),
    FLR::scaled(-8296327868244873, -54),
    FLR::scaled(7995146927371163, -53),
    FLR::scaled(5440455523270994, -54),
    FLR::scaled(8586617456218381, -53),
    FLR::scaled(-8586617456218381, -53),
    FLR::scaled(5440455523270994, -54),
    FLR::scaled(8650789058710388, -53),
    FLR::scaled(5017364677319486, -54),
    FLR::scaled(-5017364677319486, -54),
    FLR::scaled(8650789058710388, -53),
    FLR::scaled(8686250625038550, -54),
    FLR::scaled(7890937899537737, -53),
    FLR::scaled(-7890937899537737, -53),
    FLR::scaled(8686250625038550, -54),
    FLR::scaled(7032255783343117, -53),
    FLR::scaled(5628233915913940, -53),
    FLR::scaled(-5628233915913940, -53),
    FLR::scaled(7032255783343117, -53),
    FLR::scaled(7942347067146965, -56),
    FLR::scaled(8952318119487099, -53),
    FLR::scaled(-8952318119487099, -53),
    FLR::scaled(7942347067146965, -56),
    FLR::scaled(8855027013722231, -53),
    FLR::scaled(6594706969509681, -55),
    FLR::scaled(-6594706969509681, -55),
    FLR::scaled(8855027013722231, -53),
    FLR::scaled(5095659144473433, -53),
    FLR::scaled(7427240153512674, -53),
    FLR::scaled(-7427240153512674, -53),
    FLR::scaled(5095659144473433, -53),
    FLR::scaled(7550056943179025, -53),
    FLR::scaled(4911850829306697, -53),
    FLR::scaled(-4911850829306697, -53),
    FLR::scaled(7550056943179025, -53),
    FLR::scaled(7461973733147729, -55),
    FLR::scaled(8811899492445997, -53),
    FLR::scaled(-8811899492445997, -53),
    FLR::scaled(7461973733147729, -55),
    FLR::scaled(8363239276060827, -53),
    FLR::scaled(6689055905271015, -54),
    FLR::scaled(-6689055905271015, -54),
    FLR::scaled(8363239276060827, -53),
    FLR::scaled(7097529619223511, -54),
    FLR::scaled(8278641599964811, -53),
    FLR::scaled(-8278641599964811, -53),
    FLR::scaled(7097529619223511, -54),
    FLR::scaled(6446730156091567, -53),
    FLR::scaled(6290414033205309, -53),
    FLR::scaled(-6290414033205309, -53),
    FLR::scaled(6446730156091567, -53),
    FLR::scaled(7074060192106372, -59),
    FLR::scaled(9006521029202651, -53),
    FLR::scaled(-9006521029202651, -53),
    FLR::scaled(7074060192106372, -59),
    FLR::scaled(9007029696760466, -53),
    FLR::scaled(7074193361797233, -60),
    FLR::scaled(-7074193361797233, -60),
    FLR::scaled(9007029696760466, -53),
    FLR::scaled(6329852010540816, -53),
    FLR::scaled(6408011543315061, -53),
    FLR::scaled(-6408011543315061, -53),
    FLR::scaled(6329852010540816, -53),
    FLR::scaled(8300260568395001, -53),
    FLR::scaled(6995802430416048, -54),
    FLR::scaled(-6995802430416048, -54),
    FLR::scaled(8300260568395001, -53),
    FLR::scaled(6791561728666308, -54),
    FLR::scaled(8342560202721672, -53),
    FLR::scaled(-8342560202721672, -53),
    FLR::scaled(6791561728666308, -54),
    FLR::scaled(8823180063448708, -53),
    FLR::scaled(7245558068298598, -55),
    FLR::scaled(-7245558068298598, -55),
    FLR::scaled(8823180063448708, -53),
    FLR::scaled(4958084643600824, -53),
    FLR::scaled(7519776265388244, -53),
    FLR::scaled(-7519776265388244, -53),
    FLR::scaled(4958084643600824, -53),
    FLR::scaled(7458366714537629, -53),
    FLR::scaled(5049990531286555, -53),
    FLR::scaled(-5049990531286555, -53),
    FLR::scaled(7458366714537629, -53),
    FLR::scaled(6811916523300038, -55),
    FLR::scaled(8844744230026167, -53),
    FLR::scaled(-8844744230026167, -53),
    FLR::scaled(6811916523300038, -55),
    FLR::scaled(8958241260309380, -53),
    FLR::scaled(7502754424118275, -56),
    FLR::scaled(-7502754424118275, -56),
    FLR::scaled(8958241260309380, -53),
    FLR::scaled(5671277076310961, -53),
    FLR::scaled(6997589209028812, -53),
    FLR::scaled(-6997589209028812, -53),
    FLR::scaled(5671277076310961, -53),
    FLR::scaled(7917438270796208, -53),
    FLR::scaled(8589251339374868, -54),
    FLR::scaled(-8589251339374868, -54),
    FLR::scaled(7917438270796208, -53),
    FLR::scaled(5123430714424177, -54),
    FLR::scaled(8635233224599694, -53),
    FLR::scaled(-8635233224599694, -53),
    FLR::scaled(5123430714424177, -54),
    FLR::scaled(8603146819336178, -53),
    FLR::scaled(5334980119757703, -54),
    FLR::scaled(-5334980119757703, -54),
    FLR::scaled(8603146819336178, -53),
    FLR::scaled(8394286290816088, -54),
    FLR::scaled(7969543765584135, -53),
    FLR::scaled(-7969543765584135, -53),
    FLR::scaled(8394286290816088, -54),
    FLR::scaled(6927467009660074, -53),
    FLR::scaled(5756721223463751, -53),
    FLR::scaled(-5756721223463751, -53),
    FLR::scaled(6927467009660074, -53),
    FLR::scaled(6622738275719969, -56),
    FLR::scaled(8969075513488470, -53),
    FLR::scaled(-8969075513488470, -53),
    FLR::scaled(6622738275719969, -56),
    FLR::scaled(8993468505216860, -53),
    FLR::scaled(7954473020348387, -57),
    FLR::scaled(-7954473020348387, -57),
    FLR::scaled(8993468505216860, -53),
    FLR::scaled(6007801203085623, -53),
    FLR::scaled(6710883929767346, -53),
    FLR::scaled(-6710883929767346, -53),
    FLR::scaled(6007801203085623, -53),
    FLR::scaled(8118628663374582, -53),
    FLR::scaled(7801924644814081, -54),
    FLR::scaled(-7801924644814081, -54),
    FLR::scaled(8118628663374582, -53),
    FLR::scaled(5964680940960804, -54),
    FLR::scaled(8499134293134885, -53),
    FLR::scaled(-8499134293134885, -53),
    FLR::scaled(5964680940960804, -54),
    FLR::scaled(8723671485748716, -53),
    FLR::scaled(8968562179829241, -55),
    FLR::scaled(-8968562179829241, -55),
    FLR::scaled(8723671485748716, -53),
    FLR::scaled(4583134480704026, -53),
    FLR::scaled(7754000048129257, -53),
    FLR::scaled(-7754000048129257, -53),
    FLR::scaled(4583134480704026, -53),
    FLR::scaled(7201591494446370, -53),
    FLR::scaled(5409872305491543, -53),
    FLR::scaled(-5409872305491543, -53),
    FLR::scaled(7201591494446370, -53),
    FLR::scaled(5067747153968079, -55),
    FLR::scaled(8917651573624763, -53),
    FLR::scaled(-8917651573624763, -53),
    FLR::scaled(5067747153968079, -55),
    FLR::scaled(8901432827556552, -53),
    FLR::scaled(5505098772745492, -55),
    FLR::scaled(-5505098772745492, -55),
    FLR::scaled(8901432827556552, -53),
    FLR::scaled(5321090346314263, -53),
    FLR::scaled(7267436682969301, -53),
    FLR::scaled(-7267436682969301, -53),
    FLR::scaled(5321090346314263, -53),
    FLR::scaled(7697174075937797, -53),
    FLR::scaled(4677942887564769, -53),
    FLR::scaled(-4677942887564769, -53),
    FLR::scaled(7697174075937797, -53),
    FLR::scaled(8539675389073947, -55),
    FLR::scaled(8750529122869341, -53),
    FLR::scaled(-8750529122869341, -53),
    FLR::scaled(8539675389073947, -55),
    FLR::scaled(8461896418689196, -53),
    FLR::scaled(6172826715203219, -54),
    FLR::scaled(-6172826715203219, -54),
    FLR::scaled(8461896418689196, -53),
    FLR::scaled(7602081049296905, -54),
    FLR::scaled(8165888154058130, -53),
    FLR::scaled(-8165888154058130, -53),
    FLR::scaled(7602081049296905, -54),
    FLR::scaled(6636653650073061, -53),
    FLR::scaled(6089701695779408, -53),
    FLR::scaled(-6089701695779408, -53),
    FLR::scaled(6636653650073061, -53),
    FLR::scaled(6188054973828419, -57),
    FLR::scaled(8998892164841951, -53),
    FLR::scaled(-8998892164841951, -53),
    FLR::scaled(6188054973828419, -57),
    FLR::scaled(9002960624407544, -53),
    FLR::scaled(8841410057981697, -58),
    FLR::scaled(-8841410057981697, -58),
    FLR::scaled(9002960624407544, -53),
    FLR::scaled(6170685101797492, -53),
    FLR::scaled(6561423914750605, -53),
    FLR::scaled(-6561423914750605, -53),
    FLR::scaled(6170685101797492, -53),
    FLR::scaled(8211917892022175, -53),
    FLR::scaled(7401092608336357, -54),
    FLR::scaled(-7401092608336357, -54),
    FLR::scaled(8211917892022175, -53),
    FLR::scaled(6380042884447767, -54),
    FLR::scaled(8423384213768154, -53),
    FLR::scaled(-8423384213768154, -53),
    FLR::scaled(6380042884447767, -54),
    FLR::scaled(8776068962491037, -53),
    FLR::scaled(8109502554616454, -55),
    FLR::scaled(-8109502554616454, -55),
    FLR::scaled(8776068962491037, -53),
    FLR::scaled(4772046813433470, -53),
    FLR::scaled(7639188937642932, -53),
    FLR::scaled(-7639188937642932, -53),
    FLR::scaled(4772046813433470, -53),
    FLR::scaled(7332187422259511, -53),
    FLR::scaled(5231507050503336, -53),
    FLR::scaled(-5231507050503336, -53),
    FLR::scaled(7332187422259511, -53),
    FLR::scaled(5941621343897074, -55),
    FLR::scaled(8883873558446555, -53),
    FLR::scaled(-8883873558446555, -53),
    FLR::scaled(5941621343897074, -55),
    FLR::scaled(8932527354167686, -53),
    FLR::scaled(4629632351109917, -55),
    FLR::scaled(-4629632351109917, -55),
    FLR::scaled(8932527354167686, -53),
    FLR::scaled(5497839557798690, -53),
    FLR::scaled(7134661772733911, -53),
    FLR::scaled(-7134661772733911, -53),
    FLR::scaled(5497839557798690, -53),
    FLR::scaled(7809658296434922, -53),
    FLR::scaled(8975271741297168, -54),
    FLR::scaled(-8975271741297168, -54),
    FLR::scaled(7809658296434922, -53),
    FLR::scaled(4698049169054608, -54),
    FLR::scaled(8695500095790524, -53),
    FLR::scaled(-8695500095790524, -53),
    FLR::scaled(4698049169054608, -54),
    FLR::scaled(8535092229218300, -53),
    FLR::scaled(5755636907708500, -54),
    FLR::scaled(-5755636907708500, -54),
    FLR::scaled(8535092229218300, -53),
    FLR::scaled(8000593299177483, -54),
    FLR::scaled(8070146537076992, -53),
    FLR::scaled(-8070146537076992, -53),
    FLR::scaled(8000593299177483, -54),
    FLR::scaled(6784103575026380, -53),
    FLR::scaled(5924995957629083, -53),
    FLR::scaled(-5924995957629083, -53),
    FLR::scaled(6784103575026380, -53),
    FLR::scaled(4859846576245171, -56),
    FLR::scaled(8986690462315460, -53),
    FLR::scaled(-8986690462315460, -53),
    FLR::scaled(4859846576245171, -56),
    FLR::scaled(8978559056886080, -53),
    FLR::scaled(5741724767297686, -56),
    FLR::scaled(-5741724767297686, -56),
    FLR::scaled(8978559056886080, -53),
    FLR::scaled(5841298429575172, -53),
    FLR::scaled(6856301559240908, -53),
    FLR::scaled(-6856301559240908, -53),
    FLR::scaled(5841298429575172, -53),
    FLR::scaled(8020449076395251, -53),
    FLR::scaled(8198057093618523, -54),
    FLR::scaled(-8198057093618523, -54),
    FLR::scaled(8020449076395251, -53),
    FLR::scaled(5545726096708791, -54),
    FLR::scaled(8569764811806532, -53),
    FLR::scaled(-8569764811806532, -53),
    FLR::scaled(5545726096708791, -54),
    FLR::scaled(8666019195502468, -53),
    FLR::scaled(4911109739270519, -54),
    FLR::scaled(-4911109739270519, -54),
    FLR::scaled(8666019195502468, -53),
    FLR::scaled(8782922878275687, -54),
    FLR::scaled(7864140438927325, -53),
    FLR::scaled(-7864140438927325, -53),
    FLR::scaled(8782922878275687, -54),
    FLR::scaled(7066657597201826, -53),
    FLR::scaled(5584978855691076, -53),
    FLR::scaled(-5584978855691076, -53),
    FLR::scaled(7066657597201826, -53),
    FLR::scaled(8381640685297609, -56),
    FLR::scaled(8946057928947489, -53),
    FLR::scaled(-8946057928947489, -53),
    FLR::scaled(8381640685297609, -56),
    FLR::scaled(8864976410656110, -53),
    FLR::scaled(6377249128729266, -55),
    FLR::scaled(-6377249128729266, -55),
    FLR::scaled(8864976410656110, -53),
    FLR::scaled(5141135908973599, -53),
    FLR::scaled(7395833961093832, -53),
    FLR::scaled(-7395833961093832, -53),
    FLR::scaled(5141135908973599, -53),
    FLR::scaled(7580053365593204, -53),
    FLR::scaled(4865432086605035, -53),
    FLR::scaled(-4865432086605035, -53),
    FLR::scaled(7580053365593204, -53),
    FLR::scaled(7678108458903330, -55),
    FLR::scaled(8800287158407901, -53),
    FLR::scaled(-8800287158407901, -53),
    FLR::scaled(7678108458903330, -55),
    FLR::scaled(8383603478168160, -53),
    FLR::scaled(6586298242701558, -54),
    FLR::scaled(-6586298242701558, -54),
    FLR::scaled(8383603478168160, -53),
    FLR::scaled(7198989590052351, -54),
    FLR::scaled(8256710945357489, -53),
    FLR::scaled(-8256710945357489, -53),
    FLR::scaled(7198989590052351, -54),
    FLR::scaled(6485206053121402, -53),
    FLR::scaled(6250739225336809, -53),
    FLR::scaled(-6250739225336809, -53),
    FLR::scaled(6485206053121402, -53),
    FLR::scaled(5305378684473085, -58),
    FLR::scaled(9005673271218593, -53),
    FLR::scaled(-9005673271218593, -53),
    FLR::scaled(5305378684473085, -58),
    FLR::scaled(9005673271218593, -53),
    FLR::scaled(5305378684473085, -58),
    FLR::scaled(-5305378684473085, -58),
    FLR::scaled(9005673271218593, -53),
    FLR::scaled(6250739225336809, -53),
    FLR::scaled(6485206053121402, -53),
    FLR::scaled(-6485206053121402, -53),
    FLR::scaled(6250739225336809, -53),
    FLR::scaled(8256710945357489, -53),
    FLR::scaled(7198989590052351, -54),
    FLR::scaled(-7198989590052351, -54),
    FLR::scaled(8256710945357489, -53),
    FLR::scaled(6586298242701558, -54),
    FLR::scaled(8383603478168160, -53),
    FLR::scaled(-8383603478168160, -53),
    FLR::scaled(6586298242701558, -54),
    FLR::scaled(8800287158407901, -53),
    FLR::scaled(7678108458903330, -55),
    FLR::scaled(-7678108458903330, -55),
    FLR::scaled(8800287158407901, -53),
    FLR::scaled(4865432086605035, -53),
    FLR::scaled(7580053365593204, -53),
    FLR::scaled(-7580053365593204, -53),
    FLR::scaled(4865432086605035, -53),
    FLR::scaled(7395833961093832, -53),
    FLR::scaled(5141135908973599, -53),
    FLR::scaled(-5141135908973599, -53),
    FLR::scaled(7395833961093832, -53),
    FLR::scaled(6377249128729266, -55),
    FLR::scaled(8864976410656110, -53),
    FLR::scaled(-8864976410656110, -53),
    FLR::scaled(6377249128729266, -55),
    FLR::scaled(8946057928947489, -53),
    FLR::scaled(8381640685297609, -56),
    FLR::scaled(-8381640685297609, -56),
    FLR::scaled(8946057928947489, -53),
    FLR::scaled(5584978855691076, -53),
    FLR::scaled(7066657597201826, -53),
    FLR::scaled(-7066657597201826, -53),
    FLR::scaled(5584978855691076, -53),
    FLR::scaled(7864140438927325, -53),
    FLR::scaled(8782922878275687, -54),
    FLR::scaled(-8782922878275687, -54),
    FLR::scaled(7864140438927325, -53),
    FLR::scaled(4911109739270519, -54),
    FLR::scaled(8666019195502468, -53),
    FLR::scaled(-8666019195502468, -53),
    FLR::scaled(4911109739270519, -54),
    FLR::scaled(8569764811806532, -53),
    FLR::scaled(5545726096708791, -54),
    FLR::scaled(-5545726096708791, -54),
    FLR::scaled(8569764811806532, -53),
    FLR::scaled(8198057093618523, -54),
    FLR::scaled(8020449076395251, -53),
    FLR::scaled(-8020449076395251, -53),
    FLR::scaled(8198057093618523, -54),
    FLR::scaled(6856301559240908, -53),
    FLR::scaled(5841298429575172, -53),
    FLR::scaled(-5841298429575172, -53),
    FLR::scaled(6856301559240908, -53),
    FLR::scaled(5741724767297686, -56),
    FLR::scaled(8978559056886080, -53),
    FLR::scaled(-8978559056886080, -53),
    FLR::scaled(5741724767297686, -56),
    FLR::scaled(8986690462315460, -53),
    FLR::scaled(4859846576245171, -56),
    FLR::scaled(-4859846576245171, -56),
    FLR::scaled(8986690462315460, -53),
    FLR::scaled(5924995957629083, -53),
    FLR::scaled(6784103575026380, -53),
    FLR::scaled(-6784103575026380, -53),
    FLR::scaled(5924995957629083, -53),
    FLR::scaled(8070146537076992, -53),
    FLR::scaled(8000593299177483, -54),
    FLR::scaled(-8000593299177483, -54),
    FLR::scaled(8070146537076992, -53),
    FLR::scaled(5755636907708500, -54),
    FLR::scaled(8535092229218300, -53),
    FLR::scaled(-8535092229218300, -53),
    FLR::scaled(5755636907708500, -54),
    FLR::scaled(8695500095790524, -53),
    FLR::scaled(4698049169054608, -54),
    FLR::scaled(-4698049169054608, -54),
    FLR::scaled(8695500095790524, -53),
    FLR::scaled(8975271741297168, -54),
    FLR::scaled(7809658296434922, -53),
    FLR::scaled(-7809658296434922, -53),
    FLR::scaled(8975271741297168, -54),
    FLR::scaled(7134661772733911, -53),
    FLR::scaled(5497839557798690, -53),
    FLR::scaled(-5497839557798690, -53),
    FLR::scaled(7134661772733911, -53),
    FLR::scaled(4629632351109917, -55),
    FLR::scaled(8932527354167686, -53),
    FLR::scaled(-8932527354167686, -53),
    FLR::scaled(4629632351109917, -55),
    FLR::scaled(8883873558446555, -53),
    FLR::scaled(5941621343897074, -55),
    FLR::scaled(-5941621343897074, -55),
    FLR::scaled(8883873558446555, -53),
    FLR::scaled(5231507050503336, -53),
    FLR::scaled(7332187422259511, -53),
    FLR::scaled(-7332187422259511, -53),
    FLR::scaled(5231507050503336, -53),
    FLR::scaled(7639188937642932, -53),
    FLR::scaled(4772046813433470, -53),
    FLR::scaled(-4772046813433470, -53),
    FLR::scaled(7639188937642932, -53),
    FLR::scaled(8109502554616454, -55),
    FLR::scaled(8776068962491037, -53),
    FLR::scaled(-8776068962491037, -53),
    FLR::scaled(8109502554616454, -55),
    FLR::scaled(8423384213768154, -53),
    FLR::scaled(6380042884447767, -54),
    FLR::scaled(-6380042884447767, -54),
    FLR::scaled(8423384213768154, -53),
    FLR::scaled(7401092608336357, -54),
    FLR::scaled(8211917892022175, -53),
    FLR::scaled(-8211917892022175, -53),
    FLR::scaled(7401092608336357, -54),
    FLR::scaled(6561423914750605, -53),
    FLR::scaled(6170685101797492, -53),
    FLR::scaled(-6170685101797492, -53),
    FLR::scaled(6561423914750605, -53),
    FLR::scaled(8841410057981697, -58),
    FLR::scaled(9002960624407544, -53),
    FLR::scaled(-9002960624407544, -53),
    FLR::scaled(8841410057981697, -58),
    FLR::scaled(8998892164841951, -53),
    FLR::scaled(6188054973828419, -57),
    FLR::scaled(-6188054973828419, -57),
    FLR::scaled(8998892164841951, -53),
    FLR::scaled(6089701695779408, -53),
    FLR::scaled(6636653650073061, -53),
    FLR::scaled(-6636653650073061, -53),
    FLR::scaled(6089701695779408, -53),
    FLR::scaled(8165888154058130, -53),
    FLR::scaled(7602081049296905, -54),
    FLR::scaled(-7602081049296905, -54),
    FLR::scaled(8165888154058130, -53),
    FLR::scaled(6172826715203219, -54),
    FLR::scaled(8461896418689196, -53),
    FLR::scaled(-8461896418689196, -53),
    FLR::scaled(6172826715203219, -54),
    FLR::scaled(8750529122869341, -53),
    FLR::scaled(8539675389073947, -55),
    FLR::scaled(-8539675389073947, -55),
    FLR::scaled(8750529122869341, -53),
    FLR::scaled(4677942887564769, -53),
    FLR::scaled(7697174075937797, -53),
    FLR::scaled(-7697174075937797, -53),
    FLR::scaled(4677942887564769, -53),
    FLR::scaled(7267436682969301, -53),
    FLR::scaled(5321090346314263, -53),
    FLR::scaled(-5321090346314263, -53),
    FLR::scaled(7267436682969301, -53),
    FLR::scaled(5505098772745492, -55),
    FLR::scaled(8901432827556552, -53),
    FLR::scaled(-8901432827556552, -53),
    FLR::scaled(5505098772745492, -55),
    FLR::scaled(8917651573624763, -53),
    FLR::scaled(5067747153968079, -55),
    FLR::scaled(-5067747153968079, -55),
    FLR::scaled(8917651573624763, -53),
    FLR::scaled(5409872305491543, -53),
    FLR::scaled(7201591494446370, -53),
    FLR::scaled(-7201591494446370, -53),
    FLR::scaled(5409872305491543, -53),
    FLR::scaled(7754000048129257, -53),
    FLR::scaled(4583134480704026, -53),
    FLR::scaled(-4583134480704026, -53),
    FLR::scaled(7754000048129257, -53),
    FLR::scaled(8968562179829241, -55),
    FLR::scaled(8723671485748716, -53),
    FLR::scaled(-8723671485748716, -53),
    FLR::scaled(8968562179829241, -55),
    FLR::scaled(8499134293134885, -53),
    FLR::scaled(5964680940960804, -54),
    FLR::scaled(-5964680940960804, -54),
    FLR::scaled(8499134293134885, -53),
    FLR::scaled(7801924644814081, -54),
    FLR::scaled(8118628663374582, -53),
    FLR::scaled(-8118628663374582, -53),
    FLR::scaled(7801924644814081, -54),
    FLR::scaled(6710883929767346, -53),
    FLR::scaled(6007801203085623, -53),
    FLR::scaled(-6007801203085623, -53),
    FLR::scaled(6710883929767346, -53),
    FLR::scaled(7954473020348387, -57),
    FLR::scaled(8993468505216860, -53),
    FLR::scaled(-8993468505216860, -53),
    FLR::scaled(7954473020348387, -57),
    FLR::scaled(8969075513488470, -53),
    FLR::scaled(6622738275719969, -56),
    FLR::scaled(-6622738275719969, -56),
    FLR::scaled(8969075513488470, -53),
    FLR::scaled(5756721223463751, -53),
    FLR::scaled(6927467009660074, -53),
    FLR::scaled(-6927467009660074, -53),
    FLR::scaled(5756721223463751, -53),
    FLR::scaled(7969543765584135, -53),
    FLR::scaled(8394286290816088, -54),
    FLR::scaled(-8394286290816088, -54),
    FLR::scaled(7969543765584135, -53),
    FLR::scaled(5334980119757703, -54),
    FLR::scaled(8603146819336178, -53),
    FLR::scaled(-8603146819336178, -53),
    FLR::scaled(5334980119757703, -54),
    FLR::scaled(8635233224599694, -53),
    FLR::scaled(5123430714424177, -54),
    FLR::scaled(-5123430714424177, -54),
    FLR::scaled(8635233224599694, -53),
    FLR::scaled(8589251339374868, -54),
    FLR::scaled(7917438270796208, -53),
    FLR::scaled(-7917438270796208, -53),
    FLR::scaled(8589251339374868, -54),
    FLR::scaled(6997589209028812, -53),
    FLR::scaled(5671277076310961, -53),
    FLR::scaled(-5671277076310961, -53),
    FLR::scaled(6997589209028812, -53),
    FLR::scaled(7502754424118275, -56),
    FLR::scaled(8958241260309380, -53),
    FLR::scaled(-8958241260309380, -53),
    FLR::scaled(7502754424118275, -56),
    FLR::scaled(8844744230026167, -53),
    FLR::scaled(6811916523300038, -55),
    FLR::scaled(-6811916523300038, -55),
    FLR::scaled(8844744230026167, -53),
    FLR::scaled(5049990531286555, -53),
    FLR::scaled(7458366714537629, -53),
    FLR::scaled(-7458366714537629, -53),
    FLR::scaled(5049990531286555, -53),
    FLR::scaled(7519776265388244, -53),
    FLR::scaled(4958084643600824, -53),
    FLR::scaled(-4958084643600824, -53),
    FLR::scaled(7519776265388244, -53),
    FLR::scaled(7245558068298598, -55),
    FLR::scaled(8823180063448708, -53),
    FLR::scaled(-8823180063448708, -53),
    FLR::scaled(7245558068298598, -55),
    FLR::scaled(8342560202721672, -53),
    FLR::scaled(6791561728666308, -54),
    FLR::scaled(-6791561728666308, -54),
    FLR::scaled(8342560202721672, -53),
    FLR::scaled(6995802430416048, -54),
    FLR::scaled(8300260568395001, -53),
    FLR::scaled(-8300260568395001, -53),
    FLR::scaled(6995802430416048, -54),
    FLR::scaled(6408011543315061, -53),
    FLR::scaled(6329852010540816, -53),
    FLR::scaled(-6329852010540816, -53),
    FLR::scaled(6408011543315061, -53),
    FLR::scaled(7074193361797233, -60),
    FLR::scaled(9007029696760466, -53),
    FLR::scaled(-9007029696760466, -53),
    FLR::scaled(7074193361797233, -60),
    FLR::scaled(9007156865146114, -53),
    FLR::scaled(7074226654454970, -61),
    FLR::scaled(-7074226654454970, -61),
    FLR::scaled(9007156865146114, -53),
    FLR::scaled(6349481723403377, -53),
    FLR::scaled(6388561673708188, -53),
    FLR::scaled(-6388561673708188, -53),
    FLR::scaled(6349481723403377, -53),
    FLR::scaled(8310952915477583, -53),
    FLR::scaled(6944839825747268, -54),
    FLR::scaled(-6944839825747268, -54),
    FLR::scaled(8310952915477583, -53),
    FLR::scaled(6842718994272319, -54),
    FLR::scaled(8332102832176454, -53),
    FLR::scaled(-8332102832176454, -53),
    FLR::scaled(6842718994272319, -54),
    FLR::scaled(8828695804602461, -53),
    FLR::scaled(7137247429536506, -55),
    FLR::scaled(-7137247429536506, -55),
    FLR::scaled(8828695804602461, -53),
    FLR::scaled(4981131658359743, -53),
    FLR::scaled(7504529686575502, -53),
    FLR::scaled(-7504529686575502, -53),
    FLR::scaled(4981131658359743, -53),
    FLR::scaled(7473824766646994, -53),
    FLR::scaled(5027084818466930, -53),
    FLR::scaled(-5027084818466930, -53),
    FLR::scaled(7473824766646994, -53),
    FLR::scaled(6920425636632580, -55),
    FLR::scaled(8839477938633966, -53),
    FLR::scaled(-8839477938633966, -53),
    FLR::scaled(6920425636632580, -55),
    FLR::scaled(8961076366892190, -53),
    FLR::scaled(7282851139856476, -56),
    FLR::scaled(-7282851139856476, -56),
    FLR::scaled(8961076366892190, -53),
    FLR::scaled(5692718687339392, -53),
    FLR::scaled(6980157044180565, -53),
    FLR::scaled(-6980157044180565, -53),
    FLR::scaled(5692718687339392, -53),
    FLR::scaled(7930576735691761, -53),
    FLR::scaled(8540630200145957, -54),
    FLR::scaled(-8540630200145957, -54),
    FLR::scaled(7930576735691761, -53),
    FLR::scaled(5176391646926010, -54),
    FLR::scaled(8627333353592832, -53),
    FLR::scaled(-8627333353592832, -53),
    FLR::scaled(5176391646926010, -54),
    FLR::scaled(8611290075458352, -53),
    FLR::scaled(5282166847391008, -54),
    FLR::scaled(-5282166847391008, -54),
    FLR::scaled(8611290075458352, -53),
    FLR::scaled(8443147217093086, -54),
    FLR::scaled(7956629605695492, -53),
    FLR::scaled(-7956629605695492, -53),
    FLR::scaled(8443147217093086, -54),
    FLR::scaled(6945095779491208, -53),
    FLR::scaled(5735440961974946, -53),
    FLR::scaled(-5735440961974946, -53),
    FLR::scaled(6945095779491208, -53),
    FLR::scaled(6842840994885793, -56),
    FLR::scaled(8966493518975884, -53),
    FLR::scaled(-8966493518975884, -53),
    FLR::scaled(6842840994885793, -56),
    FLR::scaled(8994951428947667, -53),
    FLR::scaled(7512970424714007, -57),
    FLR::scaled(-7512970424714007, -57),
    FLR::scaled(8994951428947667, -53),
    FLR::scaled(6028361630966943, -53),
    FLR::scaled(6692420672738099, -53),
    FLR::scaled(-6692420672738099, -53),
    FLR::scaled(6028361630966943, -53),
    FLR::scaled(8130558439301216, -53),
    FLR::scaled(7752072724043411, -54),
    FLR::scaled(-7752072724043411, -54),
    FLR::scaled(8130558439301216, -53),
    FLR::scaled(6016802823104436, -54),
    FLR::scaled(8489944602974586, -53),
    FLR::scaled(-8489944602974586, -53),
    FLR::scaled(6016802823104436, -54),
    FLR::scaled(8730509220737932, -53),
    FLR::scaled(8861464584337410, -55),
    FLR::scaled(-8861464584337410, -55),
    FLR::scaled(8730509220737932, -53),
    FLR::scaled(4606901848488119, -53),
    FLR::scaled(7739902697902825, -53),
    FLR::scaled(-7739902697902825, -53),
    FLR::scaled(4606901848488119, -53),
    FLR::scaled(7218154856711858, -53),
    FLR::scaled(5387752674272799, -53),
    FLR::scaled(-5387752674272799, -53),
    FLR::scaled(7218154856711858, -53),
    FLR::scaled(5177159182005257, -55),
    FLR::scaled(8913722698169820, -53),
    FLR::scaled(-8913722698169820, -53),
    FLR::scaled(5177159182005257, -55),
    FLR::scaled(8905613286971281, -53),
    FLR::scaled(5395836020528807, -55),
    FLR::scaled(-5395836020528807, -55),
    FLR::scaled(8905613286971281, -53),
    FLR::scaled(5343361485770773, -53),
    FLR::scaled(7251077605914050, -53),
    FLR::scaled(-7251077605914050, -53),
    FLR::scaled(5343361485770773, -53),
    FLR::scaled(7711489578089543, -53),
    FLR::scaled(4654306275012748, -53),
    FLR::scaled(-4654306275012748, -53),
    FLR::scaled(7711489578089543, -53),
    FLR::scaled(8647020179743560, -55),
    FLR::scaled(8743938102497119, -53),
    FLR::scaled(-8743938102497119, -53),
    FLR::scaled(8647020179743560, -55),
    FLR::scaled(8471325578127065, -53),
    FLR::scaled(6120876200014774, -54),
    FLR::scaled(-6120876200014774, -54),
    FLR::scaled(8471325578127065, -53),
    FLR::scaled(7652150456031602, -54),
    FLR::scaled(8154188295849595, -53),
    FLR::scaled(-8154188295849595, -53),
    FLR::scaled(7652150456031602, -54),
    FLR::scaled(6655305358219218, -53),
    FLR::scaled(6069312070034399, -53),
    FLR::scaled(-6069312070034399, -53),
    FLR::scaled(6655305358219218, -53),
    FLR::scaled(6629757244884614, -57),
    FLR::scaled(8997663271522660, -53),
    FLR::scaled(-8997663271522660, -53),
    FLR::scaled(6629757244884614, -57),
    FLR::scaled(9003765913003641, -53),
    FLR::scaled(7957506242722589, -58),
    FLR::scaled(-7957506242722589, -58),
    FLR::scaled(9003765913003641, -53),
    FLR::scaled(6190786226252304, -53),
    FLR::scaled(6542461640350018, -53),
    FLR::scaled(-6542461640350018, -53),
    FLR::scaled(6190786226252304, -53),
    FLR::scaled(8223232361233372, -53),
    FLR::scaled(7350670159317696, -54),
    FLR::scaled(-7350670159317696, -54),
    FLR::scaled(8223232361233372, -53),
    FLR::scaled(6431698015882422, -54),
    FLR::scaled(8413557723860353, -53),
    FLR::scaled(-8413557723860353, -53),
    FLR::scaled(6431698015882422, -54),
    FLR::scaled(8782247561441008, -53),
    FLR::scaled(8001765989250269, -55),
    FLR::scaled(-8001765989250269, -55),
    FLR::scaled(8782247561441008, -53),
    FLR::scaled(4795461056637271, -53),
    FLR::scaled(7624512552870645, -53),
    FLR::scaled(-7624512552870645, -53),
    FLR::scaled(4795461056637271, -53),
    FLR::scaled(7348202953025374, -53),
    FLR::scaled(5208987596045498, -53),
    FLR::scaled(-5208987596045498, -53),
    FLR::scaled(7348202953025374, -53),
    FLR::scaled(6050614741355486, -55),
    FLR::scaled(8879274589899640, -53),
    FLR::scaled(-8879274589899640, -53),
    FLR::scaled(6050614741355486, -55),
    FLR::scaled(8936036193963400, -53),
    FLR::scaled(4519992132352091, -55),
    FLR::scaled(-4519992132352091, -55),
    FLR::scaled(8936036193963400, -53),
    FLR::scaled(5519702517755945, -53),
    FLR::scaled(7117761061603948, -53),
    FLR::scaled(-7117761061603948, -53),
    FLR::scaled(5519702517755945, -53),
    FLR::scaled(7823389415514919, -53),
    FLR::scaled(8927310113985246, -54),
    FLR::scaled(-8927310113985246, -54),
    FLR::scaled(7823389415514919, -53),
    FLR::scaled(4751381895793102, -54),
    FLR::scaled(8688252467250769, -53),
    FLR::scaled(-8688252467250769, -53),
    FLR::scaled(4751381895793102, -54),
    FLR::scaled(8543881084037075, -53),
    FLR::scaled(5703239232730864, -54),
    FLR::scaled(-5703239232730864, -54),
    FLR::scaled(8543881084037075, -53),
    FLR::scaled(8050073368155017, -54),
    FLR::scaled(8057835820270665, -53),
    FLR::scaled(-8057835820270665, -53),
    FLR::scaled(8050073368155017, -54),
    FLR::scaled(6802249279161855, -53),
    FLR::scaled(5904154737026182, -53),
    FLR::scaled(-5904154737026182, -53),
    FLR::scaled(6802249279161855, -53),
    FLR::scaled(5080389927126093, -56),
    FLR::scaled(8984784444342543, -53),
    FLR::scaled(-8984784444342543, -53),
    FLR::scaled(5080389927126093, -56),
    FLR::scaled(8980718722493792, -53),
    FLR::scaled(5521331097805465, -56),
    FLR::scaled(-5521331097805465, -56),
    FLR::scaled(8980718722493792, -53),
    FLR::scaled(5862305776050047, -53),
    FLR::scaled(6838348441158650, -53),
    FLR::scaled(-6838348441158650, -53),
    FLR::scaled(5862305776050047, -53),
    FLR::scaled(8032986972986387, -53),
    FLR::scaled(8148805730028833, -54),
    FLR::scaled(-8148805730028833, -54),
    FLR::scaled(8032986972986387, -53),
    FLR::scaled(5598283333288561, -54),
    FLR::scaled(8561217456919463, -53),
    FLR::scaled(-8561217456919463, -53),
    FLR::scaled(5598283333288561, -54),
    FLR::scaled(8673511947735049, -53),
    FLR::scaled(4857912682255224, -54),
    FLR::scaled(-4857912682255224, -54),
    FLR::scaled(8673511947735049, -53),
    FLR::scaled(8831135229857187, -54),
    FLR::scaled(7850630614963393, -53),
    FLR::scaled(-7850630614963393, -53),
    FLR::scaled(8831135229857187, -54),
    FLR::scaled(7083758813816853, -53),
    FLR::scaled(5563272371750168, -53),
    FLR::scaled(-5563272371750168, -53),
    FLR::scaled(7083758813816853, -53),
    FLR::scaled(8601170191100479, -56),
    FLR::scaled(8942801513192182, -53),
    FLR::scaled(-8942801513192182, -53),
    FLR::scaled(8601170191100479, -56),
    FLR::scaled(8869825971537420, -53),
    FLR::scaled(6268429658850061, -55),
    FLR::scaled(-6268429658850061, -55),
    FLR::scaled(8869825971537420, -53),
    FLR::scaled(5163801812627728, -53),
    FLR::scaled(7380026372209606, -53),
    FLR::scaled(-7380026372209606, -53),
    FLR::scaled(5163801812627728, -53),
    FLR::scaled(7594944627693494, -53),
    FLR::scaled(4842153912968527, -53),
    FLR::scaled(-4842153912968527, -53),
    FLR::scaled(7594944627693494, -53),
    FLR::scaled(7786067926277549, -55),
    FLR::scaled(8794356716387429, -53),
    FLR::scaled(-8794356716387429, -53),
    FLR::scaled(7786067926277549, -55),
    FLR::scaled(8393667262452058, -53),
    FLR::scaled(6534826180350098, -54),
    FLR::scaled(-6534826180350098, -54),
    FLR::scaled(8393667262452058, -53),
    FLR::scaled(7249618174605810, -54),
    FLR::scaled(8245628993303844, -53),
    FLR::scaled(-8245628993303844, -53),
    FLR::scaled(7249618174605810, -54),
    FLR::scaled(6504352530186687, -53),
    FLR::scaled(6230813476397823, -53),
    FLR::scaled(-6230813476397823, -53),
    FLR::scaled(6504352530186687, -53),
    FLR::scaled(6189482235310630, -58),
    FLR::scaled(9005122242792311, -53),
    FLR::scaled(-9005122242792311, -53),
    FLR::scaled(6189482235310630, -58),
    FLR::scaled(9006139534818257, -53),
    FLR::scaled(8842450394781643, -59),
    FLR::scaled(-8842450394781643, -59),
    FLR::scaled(9006139534818257, -53),
    FLR::scaled(6270606139937627, -53),
    FLR::scaled(6465998534826869, -53),
    FLR::scaled(-6465998534826869, -53),
    FLR::scaled(6270606139937627, -53),
    FLR::scaled(8267715182103167, -53),
    FLR::scaled(7148293245867151, -54),
    FLR::scaled(-7148293245867151, -54),
    FLR::scaled(8267715182103167, -53),
    FLR::scaled(6637708312305582, -54),
    FLR::scaled(8373460784215450, -53),
    FLR::scaled(-8373460784215450, -53),
    FLR::scaled(6637708312305582, -54),
    FLR::scaled(8806134768774068, -53),
    FLR::scaled(7570076722248107, -55),
    FLR::scaled(-7570076722248107, -55),
    FLR::scaled(8806134768774068, -53),
    FLR::scaled(4888664464941756, -53),
    FLR::scaled(7565090757143791, -53),
    FLR::scaled(-7565090757143791, -53),
    FLR::scaled(4888664464941756, -53),
    FLR::scaled(7411571937572131, -53),
    FLR::scaled(5118421614990306, -53),
    FLR::scaled(-5118421614990306, -53),
    FLR::scaled(7411571937572131, -53),
    FLR::scaled(6486008573510911, -55),
    FLR::scaled(8860043409240618, -53),
    FLR::scaled(-8860043409240618, -53),
    FLR::scaled(6486008573510911, -55),
    FLR::scaled(8949230140998484, -53),
    FLR::scaled(8162032288300481, -56),
    FLR::scaled(-8162032288300481, -56),
    FLR::scaled(8949230140998484, -53),
    FLR::scaled(5606632771683968, -53),
    FLR::scaled(7049489866514174, -53),
    FLR::scaled(-7049489866514174, -53),
    FLR::scaled(5606632771683968, -53),
    FLR::scaled(7877576242606407, -53),
    FLR::scaled(8734627858479102, -54),
    FLR::scaled(-8734627858479102, -54),
    FLR::scaled(7877576242606407, -53),
    FLR::scaled(4964260571050563, -54),
    FLR::scaled(8658444875396786, -53),
    FLR::scaled(-8658444875396786, -53),
    FLR::scaled(4964260571050563, -54),
    FLR::scaled(8578231504803418, -53),
    FLR::scaled(5493116661642923, -54),
    FLR::scaled(-5493116661642923, -54),
    FLR::scaled(8578231504803418, -53),
    FLR::scaled(8247231293972637, -54),
    FLR::scaled(8007835688282839, -53),
    FLR::scaled(-8007835688282839, -53),
    FLR::scaled(8247231293972637, -54),
    FLR::scaled(6874190143201685, -53),
    FLR::scaled(5820236102574833, -53),
    FLR::scaled(-5820236102574833, -53),
    FLR::scaled(6874190143201685, -53),
    FLR::scaled(5962064393489674, -56),
    FLR::scaled(8976314881661062, -53),
    FLR::scaled(-8976314881661062, -53),
    FLR::scaled(5962064393489674, -56),
    FLR::scaled(8988511894135185, -53),
    FLR::scaled(4639257482637412, -56),
    FLR::scaled(-4639257482637412, -56),
    FLR::scaled(8988511894135185, -53),
    FLR::scaled(5945781409913510, -53),
    FLR::scaled(6765894016324346, -53),
    FLR::scaled(-6765894016324346, -53),
    FLR::scaled(5945781409913510, -53),
    FLR::scaled(8082381294590617, -53),
    FLR::scaled(7951037925568809, -54),
    FLR::scaled(-7951037925568809, -54),
    FLR::scaled(8082381294590617, -53),
    FLR::scaled(5807980408439539, -54),
    FLR::scaled(8526223038860894, -53),
    FLR::scaled(-8526223038860894, -53),
    FLR::scaled(5807980408439539, -54),
    FLR::scaled(8702665878971716, -53),
    FLR::scaled(4644672222488094, -54),
    FLR::scaled(-4644672222488094, -54),
    FLR::scaled(8702665878971716, -53),
    FLR::scaled(4511574444966625, -53),
    FLR::scaled(7795853669876749, -53),
    FLR::scaled(-7795853669876749, -53),
    FLR::scaled(4511574444966625, -53),
    FLR::scaled(7151495329710049, -53),
    FLR::scaled(5475924850081677, -53),
    FLR::scaled(-5475924850081677, -53),
    FLR::scaled(7151495329710049, -53),
    FLR::scaled(4739228994004870, -55),
    FLR::scaled(8928934438022583, -53),
    FLR::scaled(-8928934438022583, -53),
    FLR::scaled(4739228994004870, -55),
    FLR::scaled(8888388908592136, -53),
    FLR::scaled(5832572021635720, -55),
    FLR::scaled(-5832572021635720, -55),
    FLR::scaled(8888388908592136, -53),
    FLR::scaled(5253977264024408, -53),
    FLR::scaled(7316102878153182, -53),
    FLR::scaled(-7316102878153182, -53),
    FLR::scaled(5253977264024408, -53),
    FLR::scaled(7653793419459571, -53),
    FLR::scaled(4748587653907638, -53),
    FLR::scaled(-4748587653907638, -53),
    FLR::scaled(7653793419459571, -53),
    FLR::scaled(8217162790256110, -55),
    FLR::scaled(8769807759837646, -53),
    FLR::scaled(-8769807759837646, -53),
    FLR::scaled(8217162790256110, -55),
    FLR::scaled(8433131419575708, -53),
    FLR::scaled(6328327701619659, -54),
    FLR::scaled(-6328327701619659, -54),
    FLR::scaled(8433131419575708, -53),
    FLR::scaled(7451445395452699, -54),
    FLR::scaled(8200526129112289, -53),
    FLR::scaled(-8200526129112289, -53),
    FLR::scaled(7451445395452699, -54),
    FLR::scaled(6580324430530404, -53),
    FLR::scaled(6150525896504412, -53),
    FLR::scaled(-6150525896504412, -53),
    FLR::scaled(6580324430530404, -53),
    FLR::scaled(4862615327261055, -57),
    FLR::scaled(9002070596517294, -53),
    FLR::scaled(-9002070596517294, -53),
    FLR::scaled(4862615327261055, -57),
    FLR::scaled(9000036357160980, -53),
    FLR::scaled(5746294458442105, -57),
    FLR::scaled(-5746294458442105, -57),
    FLR::scaled(9000036357160980, -53),
    FLR::scaled(6110034002932808, -53),
    FLR::scaled(6617939475215195, -53),
    FLR::scaled(-6617939475215195, -53),
    FLR::scaled(6110034002932808, -53),
    FLR::scaled(8177511151817401, -53),
    FLR::scaled(7551940088880137, -54),
    FLR::scaled(-7551940088880137, -54),
    FLR::scaled(8177511151817401, -53),
    FLR::scaled(6224719129395714, -54),
    FLR::scaled(8452387612659540, -53),
    FLR::scaled(-8452387612659540, -53),
    FLR::scaled(6224719129395714, -54),
    FLR::scaled(8757037779928840, -53),
    FLR::scaled(8432250219727258, -55),
    FLR::scaled(-8432250219727258, -55),
    FLR::scaled(8757037779928840, -53),
    FLR::scaled(4701535469536748, -53),
    FLR::scaled(7682786125052197, -53),
    FLR::scaled(-7682786125052197, -53),
    FLR::scaled(4701535469536748, -53),
    FLR::scaled(7283727356142706, -53),
    FLR::scaled(5298769122728888, -53),
    FLR::scaled(-5298769122728888, -53),
    FLR::scaled(7283727356142706, -53),
    FLR::scaled(5614309708875923, -55),
    FLR::scaled(8897168584465961, -53),
    FLR::scaled(-8897168584465961, -53),
    FLR::scaled(5614309708875923, -55),
    FLR::scaled(8921496512746829, -53),
    FLR::scaled(4958287426364647, -55),
    FLR::scaled(-4958287426364647, -55),
    FLR::scaled(8921496512746829, -53),
    FLR::scaled(5431941016931809, -53),
    FLR::scaled(7184960348059028, -53),
    FLR::scaled(-7184960348059028, -53),
    FLR::scaled(5431941016931809, -53),
    FLR::scaled(7768024414754142, -53),
    FLR::scaled(4559323974712726, -53),
    FLR::scaled(-4559323974712726, -53),
    FLR::scaled(7768024414754142, -53),
    FLR::scaled(4537787679899090, -54),
    FLR::scaled(8716751640241088, -53),
    FLR::scaled(-8716751640241088, -53),
    FLR::scaled(4537787679899090, -54),
    FLR::scaled(8508243986206341, -53),
    FLR::scaled(5912502916968520, -54),
    FLR::scaled(-5912502916968520, -54),
    FLR::scaled(8508243986206341, -53),
    FLR::scaled(7851703130898649, -54),
    FLR::scaled(8106622471823008, -53),
    FLR::scaled(-8106622471823008, -53),
    FLR::scaled(7851703130898649, -54),
    FLR::scaled(6729284021401222, -53),
    FLR::scaled(5987184227491324, -53),
    FLR::scaled(-5987184227491324, -53),
    FLR::scaled(6729284021401222, -53),
    FLR::scaled(8395900745453257, -57),
    FLR::scaled(8991900931535341, -53),
    FLR::scaled(-8991900931535341, -53),
    FLR::scaled(8395900745453257, -57),
    FLR::scaled(8971573087646471, -53),
    FLR::scaled(6402573220819241, -56),
    FLR::scaled(-6402573220819241, -56),
    FLR::scaled(8971573087646471, -53),
    FLR::scaled(5777947300499967, -53),
    FLR::scaled(6909773035871137, -53),
    FLR::scaled(-6909773035871137, -53),
    FLR::scaled(5777947300499967, -53),
    FLR::scaled(7982382913091674, -53),
    FLR::scaled(8345346354319577, -54),
    FLR::scaled(-8345346354319577, -54),
    FLR::scaled(7982382913091674, -53),
    FLR::scaled(5387743177259695, -54),
    FLR::scaled(8594922587119653, -53),
    FLR::scaled(-8594922587119653, -53),
    FLR::scaled(5387743177259695, -54),
    FLR::scaled(8643051817502737, -53),
    FLR::scaled(5070421558241214, -54),
    FLR::scaled(-5070421558241214, -54),
    FLR::scaled(8643051817502737, -53),
    FLR::scaled(8637791633298976, -54),
    FLR::scaled(7904225283956311, -53),
    FLR::scaled(-7904225283956311, -53),
    FLR::scaled(8637791633298976, -54),
    FLR::scaled(7014955509902409, -53),
    FLR::scaled(5649782085062796, -53),
    FLR::scaled(-5649782085062796, -53),
    FLR::scaled(7014955509902409, -53),
    FLR::scaled(7722587089598028, -56),
    FLR::scaled(8955321835348103, -53),
    FLR::scaled(-8955321835348103, -53),
    FLR::scaled(7722587089598028, -56),
    FLR::scaled(8849927271317175, -53),
    FLR::scaled(6703343293614876, -55),
    FLR::scaled(-6703343293614876, -55),
    FLR::scaled(8849927271317175, -53),
    FLR::scaled(5072848711672022, -53),
    FLR::scaled(7442838461440245, -53),
    FLR::scaled(-7442838461440245, -53),
    FLR::scaled(5072848711672022, -53),
    FLR::scaled(7534952065202888, -53),
    FLR::scaled(4934990961460965, -53),
    FLR::scaled(-4934990961460965, -53),
    FLR::scaled(7534952065202888, -53),
    FLR::scaled(7353800509108698, -55),
    FLR::scaled(8817581275163911, -53),
    FLR::scaled(-8817581275163911, -53),
    FLR::scaled(7353800509108698, -55),
    FLR::scaled(8352939049913017, -53),
    FLR::scaled(6740340538294756, -54),
    FLR::scaled(-6740340538294756, -54),
    FLR::scaled(8352939049913017, -53),
    FLR::scaled(7046699187928017, -54),
    FLR::scaled(8289490096098815, -53),
    FLR::scaled(-8289490096098815, -53),
    FLR::scaled(7046699187928017, -54),
    FLR::scaled(6427401098276813, -53),
    FLR::scaled(6310162718700422, -53),
    FLR::scaled(-6310162718700422, -53),
    FLR::scaled(6427401098276813, -53),
    FLR::scaled(5305603405682435, -59),
    FLR::scaled(9006817750781007, -53),
    FLR::scaled(-9006817750781007, -53),
    FLR::scaled(5305603405682435, -59),
    FLR::scaled(9006817750781007, -53),
    FLR::scaled(5305603405682435, -59),
    FLR::scaled(-5305603405682435, -59),
    FLR::scaled(9006817750781007, -53),
    FLR::scaled(6310162718700422, -53),
    FLR::scaled(6427401098276813, -53),
    FLR::scaled(-6427401098276813, -53),
    FLR::scaled(6310162718700422, -53),
    FLR::scaled(8289490096098815, -53),
    FLR::scaled(7046699187928017, -54),
    FLR::scaled(-7046699187928017, -54),
    FLR::scaled(8289490096098815, -53),
    FLR::scaled(6740340538294756, -54),
    FLR::scaled(8352939049913017, -53),
    FLR::scaled(-8352939049913017, -53),
    FLR::scaled(6740340538294756, -54),
    FLR::scaled(8817581275163911, -53),
    FLR::scaled(7353800509108698, -55),
    FLR::scaled(-7353800509108698, -55),
    FLR::scaled(8817581275163911, -53),
    FLR::scaled(4934990961460965, -53),
    FLR::scaled(7534952065202888, -53),
    FLR::scaled(-7534952065202888, -53),
    FLR::scaled(4934990961460965, -53),
    FLR::scaled(7442838461440245, -53),
    FLR::scaled(5072848711672022, -53),
    FLR::scaled(-5072848711672022, -53),
    FLR::scaled(7442838461440245, -53),
    FLR::scaled(6703343293614876, -55),
    FLR::scaled(8849927271317175, -53),
    FLR::scaled(-8849927271317175, -53),
    FLR::scaled(6703343293614876, -55),
    FLR::scaled(8955321835348103, -53),
    FLR::scaled(7722587089598028, -56),
    FLR::scaled(-7722587089598028, -56),
    FLR::scaled(8955321835348103, -53),
    FLR::scaled(5649782085062796, -53),
    FLR::scaled(7014955509902409, -53),
    FLR::scaled(-7014955509902409, -53),
    FLR::scaled(5649782085062796, -53),
    FLR::scaled(7904225283956311, -53),
    FLR::scaled(8637791633298976, -54),
    FLR::scaled(-8637791633298976, -54),
    FLR::scaled(7904225283956311, -53),
    FLR::scaled(5070421558241214, -54),
    FLR::scaled(8643051817502737, -53),
    FLR::scaled(-8643051817502737, -53),
    FLR::scaled(5070421558241214, -54),
    FLR::scaled(8594922587119653, -53),
    FLR::scaled(5387743177259695, -54),
    FLR::scaled(-5387743177259695, -54),
    FLR::scaled(8594922587119653, -53),
    FLR::scaled(8345346354319577, -54),
    FLR::scaled(7982382913091674, -53),
    FLR::scaled(-7982382913091674, -53),
    FLR::scaled(8345346354319577, -54),
    FLR::scaled(6909773035871137, -53),
    FLR::scaled(5777947300499967, -53),
    FLR::scaled(-5777947300499967, -53),
    FLR::scaled(6909773035871137, -53),
    FLR::scaled(6402573220819241, -56),
    FLR::scaled(8971573087646471, -53),
    FLR::scaled(-8971573087646471, -53),
    FLR::scaled(6402573220819241, -56),
    FLR::scaled(8991900931535341, -53),
    FLR::scaled(8395900745453257, -57),
    FLR::scaled(-8395900745453257, -57),
    FLR::scaled(8991900931535341, -53),
    FLR::scaled(5987184227491324, -53),
    FLR::scaled(6729284021401222, -53),
    FLR::scaled(-6729284021401222, -53),
    FLR::scaled(5987184227491324, -53),
    FLR::scaled(8106622471823008, -53),
    FLR::scaled(7851703130898649, -54),
    FLR::scaled(-7851703130898649, -54),
    FLR::scaled(8106622471823008, -53),
    FLR::scaled(5912502916968520, -54),
    FLR::scaled(8508243986206341, -53),
    FLR::scaled(-8508243986206341, -53),
    FLR::scaled(5912502916968520, -54),
    FLR::scaled(8716751640241088, -53),
    FLR::scaled(4537787679899090, -54),
    FLR::scaled(-4537787679899090, -54),
    FLR::scaled(8716751640241088, -53),
    FLR::scaled(4559323974712726, -53),
    FLR::scaled(7768024414754142, -53),
    FLR::scaled(-7768024414754142, -53),
    FLR::scaled(4559323974712726, -53),
    FLR::scaled(7184960348059028, -53),
    FLR::scaled(5431941016931809, -53),
    FLR::scaled(-5431941016931809, -53),
    FLR::scaled(7184960348059028, -53),
    FLR::scaled(4958287426364647, -55),
    FLR::scaled(8921496512746829, -53),
    FLR::scaled(-8921496512746829, -53),
    FLR::scaled(4958287426364647, -55),
    FLR::scaled(8897168584465961, -53),
    FLR::scaled(5614309708875923, -55),
    FLR::scaled(-5614309708875923, -55),
    FLR::scaled(8897168584465961, -53),
    FLR::scaled(5298769122728888, -53),
    FLR::scaled(7283727356142706, -53),
    FLR::scaled(-7283727356142706, -53),
    FLR::scaled(5298769122728888, -53),
    FLR::scaled(7682786125052197, -53),
    FLR::scaled(4701535469536748, -53),
    FLR::scaled(-4701535469536748, -53),
    FLR::scaled(7682786125052197, -53),
    FLR::scaled(8432250219727258, -55),
    FLR::scaled(8757037779928840, -53),
    FLR::scaled(-8757037779928840, -53),
    FLR::scaled(8432250219727258, -55),
    FLR::scaled(8452387612659540, -53),
    FLR::scaled(6224719129395714, -54),
    FLR::scaled(-6224719129395714, -54),
    FLR::scaled(8452387612659540, -53),
    FLR::scaled(7551940088880137, -54),
    FLR::scaled(8177511151817401, -53),
    FLR::scaled(-8177511151817401, -53),
    FLR::scaled(7551940088880137, -54),
    FLR::scaled(6617939475215195, -53),
    FLR::scaled(6110034002932808, -53),
    FLR::scaled(-6110034002932808, -53),
    FLR::scaled(6617939475215195, -53),
    FLR::scaled(5746294458442105, -57),
    FLR::scaled(9000036357160980, -53),
    FLR::scaled(-9000036357160980, -53),
    FLR::scaled(5746294458442105, -57),
    FLR::scaled(9002070596517294, -53),
    FLR::scaled(4862615327261055, -57),
    FLR::scaled(-4862615327261055, -57),
    FLR::scaled(9002070596517294, -53),
    FLR::scaled(6150525896504412, -53),
    FLR::scaled(6580324430530404, -53),
    FLR::scaled(-6580324430530404, -53),
    FLR::scaled(6150525896504412, -53),
    FLR::scaled(8200526129112289, -53),
    FLR::scaled(7451445395452699, -54),
    FLR::scaled(-7451445395452699, -54),
    FLR::scaled(8200526129112289, -53),
    FLR::scaled(6328327701619659, -54),
    FLR::scaled(8433131419575708, -53),
    FLR::scaled(-8433131419575708, -53),
    FLR::scaled(6328327701619659, -54),
    FLR::scaled(8769807759837646, -53),
    FLR::scaled(8217162790256110, -55),
    FLR::scaled(-8217162790256110, -55),
    FLR::scaled(8769807759837646, -53),
    FLR::scaled(4748587653907638, -53),
    FLR::scaled(7653793419459571, -53),
    FLR::scaled(-7653793419459571, -53),
    FLR::scaled(4748587653907638, -53),
    FLR::scaled(7316102878153182, -53),
    FLR::scaled(5253977264024408, -53),
    FLR::scaled(-5253977264024408, -53),
    FLR::scaled(7316102878153182, -53),
    FLR::scaled(5832572021635720, -55),
    FLR::scaled(8888388908592136, -53),
    FLR::scaled(-8888388908592136, -53),
    FLR::scaled(5832572021635720, -55),
    FLR::scaled(8928934438022583, -53),
    FLR::scaled(4739228994004870, -55),
    FLR::scaled(-4739228994004870, -55),
    FLR::scaled(8928934438022583, -53),
    FLR::scaled(5475924850081677, -53),
    FLR::scaled(7151495329710049, -53),
    FLR::scaled(-7151495329710049, -53),
    FLR::scaled(5475924850081677, -53),
    FLR::scaled(7795853669876749, -53),
    FLR::scaled(4511574444966625, -53),
    FLR::scaled(-4511574444966625, -53),
    FLR::scaled(7795853669876749, -53),
    FLR::scaled(4644672222488094, -54),
    FLR::scaled(8702665878971716, -53),
    FLR::scaled(-8702665878971716, -53),
    FLR::scaled(4644672222488094, -54),
    FLR::scaled(8526223038860894, -53),
    FLR::scaled(5807980408439539, -54),
    FLR::scaled(-5807980408439539, -54),
    FLR::scaled(8526223038860894, -53),
    FLR::scaled(7951037925568809, -54),
    FLR::scaled(8082381294590617, -53),
    FLR::scaled(-8082381294590617, -53),
    FLR::scaled(7951037925568809, -54),
    FLR::scaled(6765894016324346, -53),
    FLR::scaled(5945781409913510, -53),
    FLR::scaled(-5945781409913510, -53),
    FLR::scaled(6765894016324346, -53),
    FLR::scaled(4639257482637412, -56),
    FLR::scaled(8988511894135185, -53),
    FLR::scaled(-8988511894135185, -53),
    FLR::scaled(4639257482637412, -56),
    FLR::scaled(8976314881661062, -53),
    FLR::scaled(5962064393489674, -56),
    FLR::scaled(-5962064393489674, -56),
    FLR::scaled(8976314881661062, -53),
    FLR::scaled(5820236102574833, -53),
    FLR::scaled(6874190143201685, -53),
    FLR::scaled(-6874190143201685, -53),
    FLR::scaled(5820236102574833, -53),
    FLR::scaled(8007835688282839, -53),
    FLR::scaled(8247231293972637, -54),
    FLR::scaled(-8247231293972637, -54),
    FLR::scaled(8007835688282839, -53),
    FLR::scaled(5493116661642923, -54),
    FLR::scaled(8578231504803418, -53),
    FLR::scaled(-8578231504803418, -53),
    FLR::scaled(5493116661642923, -54),
    FLR::scaled(8658444875396786, -53),
    FLR::scaled(4964260571050563, -54),
    FLR::scaled(-4964260571050563, -54),
    FLR::scaled(8658444875396786, -53),
    FLR::scaled(8734627858479102, -54),
    FLR::scaled(7877576242606407, -53),
    FLR::scaled(-7877576242606407, -53),
    FLR::scaled(8734627858479102, -54),
    FLR::scaled(7049489866514174, -53),
    FLR::scaled(5606632771683968, -53),
    FLR::scaled(-5606632771683968, -53),
    FLR::scaled(7049489866514174, -53),
    FLR::scaled(8162032288300481, -56),
    FLR::scaled(8949230140998484, -53),
    FLR::scaled(-8949230140998484, -53),
    FLR::scaled(8162032288300481, -56),
    FLR::scaled(8860043409240618, -53),
    FLR::scaled(6486008573510911, -55),
    FLR::scaled(-6486008573510911, -55),
    FLR::scaled(8860043409240618, -53),
    FLR::scaled(5118421614990306, -53),
    FLR::scaled(7411571937572131, -53),
    FLR::scaled(-7411571937572131, -53),
    FLR::scaled(5118421614990306, -53),
    FLR::scaled(7565090757143791, -53),
    FLR::scaled(4888664464941756, -53),
    FLR::scaled(-4888664464941756, -53),
    FLR::scaled(7565090757143791, -53),
    FLR::scaled(7570076722248107, -55),
    FLR::scaled(8806134768774068, -53),
    FLR::scaled(-8806134768774068, -53),
    FLR::scaled(7570076722248107, -55),
    FLR::scaled(8373460784215450, -53),
    FLR::scaled(6637708312305582, -54),
    FLR::scaled(-6637708312305582, -54),
    FLR::scaled(8373460784215450, -53),
    FLR::scaled(7148293245867151, -54),
    FLR::scaled(8267715182103167, -53),
    FLR::scaled(-8267715182103167, -53),
    FLR::scaled(7148293245867151, -54),
    FLR::scaled(6465998534826869, -53),
    FLR::scaled(6270606139937627, -53),
    FLR::scaled(-6270606139937627, -53),
    FLR::scaled(6465998534826869, -53),
    FLR::scaled(8842450394781643, -59),
    FLR::scaled(9006139534818257, -53),
    FLR::scaled(-9006139534818257, -53),
    FLR::scaled(8842450394781643, -59),
    FLR::scaled(9005122242792311, -53),
    FLR::scaled(6189482235310630, -58),
    FLR::scaled(-6189482235310630, -58),
    FLR::scaled(9005122242792311, -53),
    FLR::scaled(6230813476397823, -53),
    FLR::scaled(6504352530186687, -53),
    FLR::scaled(-6504352530186687, -53),
    FLR::scaled(6230813476397823, -53),
    FLR::scaled(8245628993303844, -53),
    FLR::scaled(7249618174605810, -54),
    FLR::scaled(-7249618174605810, -54),
    FLR::scaled(8245628993303844, -53),
    FLR::scaled(6534826180350098, -54),
    FLR::scaled(8393667262452058, -53),
    FLR::scaled(-8393667262452058, -53),
    FLR::scaled(6534826180350098, -54),
    FLR::scaled(8794356716387429, -53),
    FLR::scaled(7786067926277549, -55),
    FLR::scaled(-7786067926277549, -55),
    FLR::scaled(8794356716387429, -53),
    FLR::scaled(4842153912968527, -53),
    FLR::scaled(7594944627693494, -53),
    FLR::scaled(-7594944627693494, -53),
    FLR::scaled(4842153912968527, -53),
    FLR::scaled(7380026372209606, -53),
    FLR::scaled(5163801812627728, -53),
    FLR::scaled(-5163801812627728, -53),
    FLR::scaled(7380026372209606, -53),
    FLR::scaled(6268429658850061, -55),
    FLR::scaled(8869825971537420, -53),
    FLR::scaled(-8869825971537420, -53),
    FLR::scaled(6268429658850061, -55),
    FLR::scaled(8942801513192182, -53),
    FLR::scaled(8601170191100479, -56),
    FLR::scaled(-8601170191100479, -56),
    FLR::scaled(8942801513192182, -53),
    FLR::scaled(5563272371750168, -53),
    FLR::scaled(7083758813816853, -53),
    FLR::scaled(-7083758813816853, -53),
    FLR::scaled(5563272371750168, -53),
    FLR::scaled(7850630614963393, -53),
    FLR::scaled(8831135229857187, -54),
    FLR::scaled(-8831135229857187, -54),
    FLR::scaled(7850630614963393, -53),
    FLR::scaled(4857912682255224, -54),
    FLR::scaled(8673511947735049, -53),
    FLR::scaled(-8673511947735049, -53),
    FLR::scaled(4857912682255224, -54),
    FLR::scaled(8561217456919463, -53),
    FLR::scaled(5598283333288561, -54),
    FLR::scaled(-5598283333288561, -54),
    FLR::scaled(8561217456919463, -53),
    FLR::scaled(8148805730028833, -54),
    FLR::scaled(8032986972986387, -53),
    FLR::scaled(-8032986972986387, -53),
    FLR::scaled(8148805730028833, -54),
    FLR::scaled(6838348441158650, -53),
    FLR::scaled(5862305776050047, -53),
    FLR::scaled(-5862305776050047, -53),
    FLR::scaled(6838348441158650, -53),
    FLR::scaled(5521331097805465, -56),
    FLR::scaled(8980718722493792, -53),
    FLR::scaled(-8980718722493792, -53),
    FLR::scaled(5521331097805465, -56),
    FLR::scaled(8984784444342543, -53),
    FLR::scaled(5080389927126093, -56),
    FLR::scaled(-5080389927126093, -56),
    FLR::scaled(8984784444342543, -53),
    FLR::scaled(5904154737026182, -53),
    FLR::scaled(6802249279161855, -53),
    FLR::scaled(-6802249279161855, -53),
    FLR::scaled(5904154737026182, -53),
    FLR::scaled(8057835820270665, -53),
    FLR::scaled(8050073368155017, -54),
    FLR::scaled(-8050073368155017, -54),
    FLR::scaled(8057835820270665, -53),
    FLR::scaled(5703239232730864, -54),
    FLR::scaled(8543881084037075, -53),
    FLR::scaled(-8543881084037075, -53),
    FLR::scaled(5703239232730864, -54),
    FLR::scaled(8688252467250769, -53),
    FLR::scaled(4751381895793102, -54),
    FLR::scaled(-4751381895793102, -54),
    FLR::scaled(8688252467250769, -53),
    FLR::scaled(8927310113985246, -54),
    FLR::scaled(7823389415514919, -53),
    FLR::scaled(-7823389415514919, -53),
    FLR::scaled(8927310113985246, -54),
    FLR::scaled(7117761061603948, -53),
    FLR::scaled(5519702517755945, -53),
    FLR::scaled(-5519702517755945, -53),
    FLR::scaled(7117761061603948, -53),
    FLR::scaled(4519992132352091, -55),
    FLR::scaled(8936036193963400, -53),
    FLR::scaled(-8936036193963400, -53),
    FLR::scaled(4519992132352091, -55),
    FLR::scaled(8879274589899640, -53),
    FLR::scaled(6050614741355486, -55),
    FLR::scaled(-6050614741355486, -55),
    FLR::scaled(8879274589899640, -53),
    FLR::scaled(5208987596045498, -53),
    FLR::scaled(7348202953025374, -53),
    FLR::scaled(-7348202953025374, -53),
    FLR::scaled(5208987596045498, -53),
    FLR::scaled(7624512552870645, -53),
    FLR::scaled(4795461056637271, -53),
    FLR::scaled(-4795461056637271, -53),
    FLR::scaled(7624512552870645, -53),
    FLR::scaled(8001765989250269, -55),
    FLR::scaled(8782247561441008, -53),
    FLR::scaled(-8782247561441008, -53),
    FLR::scaled(8001765989250269, -55),
    FLR::scaled(8413557723860353, -53),
    FLR::scaled(6431698015882422, -54),
    FLR::scaled(-6431698015882422, -54),
    FLR::scaled(8413557723860353, -53),
    FLR::scaled(7350670159317696, -54),
    FLR::scaled(8223232361233372, -53),
    FLR::scaled(-8223232361233372, -53),
    FLR::scaled(7350670159317696, -54),
    FLR::scaled(6542461640350018, -53),
    FLR::scaled(6190786226252304, -53),
    FLR::scaled(-6190786226252304, -53),
    FLR::scaled(6542461640350018, -53),
    FLR::scaled(7957506242722589, -58),
    FLR::scaled(9003765913003641, -53),
    FLR::scaled(-9003765913003641, -53),
    FLR::scaled(7957506242722589, -58),
    FLR::scaled(8997663271522660, -53),
    FLR::scaled(6629757244884614, -57),
    FLR::scaled(-6629757244884614, -57),
    FLR::scaled(8997663271522660, -53),
    FLR::scaled(6069312070034399, -53),
    FLR::scaled(6655305358219218, -53),
    FLR::scaled(-6655305358219218, -53),
    FLR::scaled(6069312070034399, -53),
    FLR::scaled(8154188295849595, -53),
    FLR::scaled(7652150456031602, -54),
    FLR::scaled(-7652150456031602, -54),
    FLR::scaled(8154188295849595, -53),
    FLR::scaled(6120876200014774, -54),
    FLR::scaled(8471325578127065, -53),
    FLR::scaled(-8471325578127065, -53),
    FLR::scaled(6120876200014774, -54),
    FLR::scaled(8743938102497119, -53),
    FLR::scaled(8647020179743560, -55),
    FLR::scaled(-8647020179743560, -55),
    FLR::scaled(8743938102497119, -53),
    FLR::scaled(4654306275012748, -53),
    FLR::scaled(7711489578089543, -53),
    FLR::scaled(-7711489578089543, -53),
    FLR::scaled(4654306275012748, -53),
    FLR::scaled(7251077605914050, -53),
    FLR::scaled(5343361485770773, -53),
    FLR::scaled(-5343361485770773, -53),
    FLR::scaled(7251077605914050, -53),
    FLR::scaled(5395836020528807, -55),
    FLR::scaled(8905613286971281, -53),
    FLR::scaled(-8905613286971281, -53),
    FLR::scaled(5395836020528807, -55),
    FLR::scaled(8913722698169820, -53),
    FLR::scaled(5177159182005257, -55),
    FLR::scaled(-5177159182005257, -55),
    FLR::scaled(8913722698169820, -53),
    FLR::scaled(5387752674272799, -53),
    FLR::scaled(7218154856711858, -53),
    FLR::scaled(-7218154856711858, -53),
    FLR::scaled(5387752674272799, -53),
    FLR::scaled(7739902697902825, -53),
    FLR::scaled(4606901848488119, -53),
    FLR::scaled(-4606901848488119, -53),
    FLR::scaled(7739902697902825, -53),
    FLR::scaled(8861464584337410, -55),
    FLR::scaled(8730509220737932, -53),
    FLR::scaled(-8730509220737932, -53),
    FLR::scaled(8861464584337410, -55),
    FLR::scaled(8489944602974586, -53),
    FLR::scaled(6016802823104436, -54),
    FLR::scaled(-6016802823104436, -54),
    FLR::scaled(8489944602974586, -53),
    FLR::scaled(7752072724043411, -54),
    FLR::scaled(8130558439301216, -53),
    FLR::scaled(-8130558439301216, -53),
    FLR::scaled(7752072724043411, -54),
    FLR::scaled(6692420672738099, -53),
    FLR::scaled(6028361630966943, -53),
    FLR::scaled(-6028361630966943, -53),
    FLR::scaled(6692420672738099, -53),
    FLR::scaled(7512970424714007, -57),
    FLR::scaled(8994951428947667, -53),
    FLR::scaled(-8994951428947667, -53),
    FLR::scaled(7512970424714007, -57),
    FLR::scaled(8966493518975884, -53),
    FLR::scaled(6842840994885793, -56),
    FLR::scaled(-6842840994885793, -56),
    FLR::scaled(8966493518975884, -53),
    FLR::scaled(5735440961974946, -53),
    FLR::scaled(6945095779491208, -53),
    FLR::scaled(-6945095779491208, -53),
    FLR::scaled(5735440961974946, -53),
    FLR::scaled(7956629605695492, -53),
    FLR::scaled(8443147217093086, -54),
    FLR::scaled(-8443147217093086, -54),
    FLR::scaled(7956629605695492, -53),
    FLR::scaled(5282166847391008, -54),
    FLR::scaled(8611290075458352, -53),
    FLR::scaled(-8611290075458352, -53),
    FLR::scaled(5282166847391008, -54),
    FLR::scaled(8627333353592832, -53),
    FLR::scaled(5176391646926010, -54),
    FLR::scaled(-5176391646926010, -54),
    FLR::scaled(8627333353592832, -53),
    FLR::scaled(8540630200145957, -54),
    FLR::scaled(7930576735691761, -53),
    FLR::scaled(-7930576735691761, -53),
    FLR::scaled(8540630200145957, -54),
    FLR::scaled(6980157044180565, -53),
    FLR::scaled(5692718687339392, -53),
    FLR::scaled(-5692718687339392, -53),
    FLR::scaled(6980157044180565, -53),
    FLR::scaled(7282851139856476, -56),
    FLR::scaled(8961076366892190, -53),
    FLR::scaled(-8961076366892190, -53),
    FLR::scaled(7282851139856476, -56),
    FLR::scaled(8839477938633966, -53),
    FLR::scaled(6920425636632580, -55),
    FLR::scaled(-6920425636632580, -55),
    FLR::scaled(8839477938633966, -53),
    FLR::scaled(5027084818466930, -53),
    FLR::scaled(7473824766646994, -53),
    FLR::scaled(-7473824766646994, -53),
    FLR::scaled(5027084818466930, -53),
    FLR::scaled(7504529686575502, -53),
    FLR::scaled(4981131658359743, -53),
    FLR::scaled(-4981131658359743, -53),
    FLR::scaled(7504529686575502, -53),
    FLR::scaled(7137247429536506, -55),
    FLR::scaled(8828695804602461, -53),
    FLR::scaled(-8828695804602461, -53),
    FLR::scaled(7137247429536506, -55),
    FLR::scaled(8332102832176454, -53),
    FLR::scaled(6842718994272319, -54),
    FLR::scaled(-6842718994272319, -54),
    FLR::scaled(8332102832176454, -53),
    FLR::scaled(6944839825747268, -54),
    FLR::scaled(8310952915477583, -53),
    FLR::scaled(-8310952915477583, -53),
    FLR::scaled(6944839825747268, -54),
    FLR::scaled(6388561673708188, -53),
    FLR::scaled(6349481723403377, -53),
    FLR::scaled(-6349481723403377, -53),
    FLR::scaled(6388561673708188, -53),
    FLR::scaled(7074226654454970, -61),
    FLR::scaled(9007156865146114, -53),
    FLR::scaled(-9007156865146114, -53),
    FLR::scaled(7074226654454970, -61),
];

#[cfg(test)]
mod tests {

    use super::*;
    use crate::shake::{Shake256 as SHAKE256, Shake256Prng as SHAKE256_PRNG};

    fn rand_poly(rng: &mut SHAKE256_PRNG, f: &mut [FLR]) {
        for i in 0..f.len() {
            f[i] = FLR::from_i64(((rng.next_u16() & 0x3FF) as i64) - 512);
        }
    }

    fn poly_inner(logn: u32) {
        let n = 1usize << logn;
        let hn = n >> 1;
        let mut rng = SHAKE256_PRNG::new(&[logn as u8]);
        let mut tmp = [FLR::ZERO; 5 * 1024];
        let (f, tmp) = tmp.split_at_mut(n);
        let (g, tmp) = tmp.split_at_mut(n);
        let (h, tmp) = tmp.split_at_mut(n);
        let (f0, tmp) = tmp.split_at_mut(hn);
        let (f1, tmp) = tmp.split_at_mut(hn);
        let (g0, tmp) = tmp.split_at_mut(hn);
        let (g1, _) = tmp.split_at_mut(hn);
        for ctr in 0..(1u32 << (15 - logn)) {
            rand_poly(&mut rng, f);
            g.copy_from_slice(f);
            FFT(logn, g);
            iFFT(logn, g);
            for i in 0..n {
                assert!(f[i].rint() == g[i].rint());
            }

            if ctr < 5 {
                rand_poly(&mut rng, g);
                for i in 0..n {
                    h[i] = FLR::ZERO;
                }
                for i in 0..n {
                    for j in 0..n {
                        let s = f[i] * g[j];
                        let k = i + j;
                        if i + j < n {
                            h[k] += s;
                        } else {
                            h[k - n] -= s;
                        }
                    }
                }
                FFT(logn, f);
                FFT(logn, g);
                poly_mul_fft(logn, f, g);
                iFFT(logn, f);
                for i in 0..n {
                    assert!(f[i].rint() == h[i].rint());
                }
            }

            rand_poly(&mut rng, f);
            h.copy_from_slice(f);
            FFT(logn, f);
            poly_split_fft(logn, f0, f1, f);

            g0.copy_from_slice(f0);
            g1.copy_from_slice(f1);
            iFFT(logn - 1, g0);
            iFFT(logn - 1, g1);
            for i in 0..(n >> 1) {
                assert!(g0[i].rint() == h[2 * i].rint());
                assert!(g1[i].rint() == h[2 * i + 1].rint());
            }

            poly_merge_fft(logn, g, f0, f1);
            iFFT(logn, g);
            for i in 0..n {
                assert!(g[i].rint() == h[i].rint());
            }
        }
    }

    #[test]
    fn poly() {
        for logn in 2..11 {
            poly_inner(logn);
        }
    }

    #[test]
    fn check_GM() {
        let mut sh = SHAKE256::new();
        for i in 0..2048 {
            let x = GM[i].encode();
            sh.inject(&x);
        }
        sh.flip();
        let mut buf = [0u8; 32];
        sh.extract(&mut buf);
        // Reference hash was obtained from the constants in the Falcon
        // reference code, which were initially computed with Sage with
        // large precision.
        assert!(
            buf[..]
                == hex::decode("f45a496cf56ccc6e3e3395a20209206d81d71a7905a661447bd5bc0e24e0af1e")
                    .unwrap()
        );
    }
}
