/*
 * One FN-DSA API test vector from the C reference, through its public API
 * (fndsa.h) only. Driven by gen_api_vectors.py; not part of the crate.
 *
 * Usage: api_vector <logn> <key_seed_hex> <ctx_hex> <mode> <hv_hex> <sign_seed_hex>
 *   mode: raw | sha256 | sha512 | sha3_256 | sha3_512 | extmu
 *   hv:   the message for raw, the digest for a pre-hash mode, and for
 *         extmu the raw message from which mu is computed (with ctx).
 * Prints: sk, vk, mu, sig (hex), one per line.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fndsa.h"

static size_t unhex(const char *s, unsigned char *out, size_t max) {
	size_t n = strlen(s) / 2;
	if (n > max) { fprintf(stderr, "input too long\n"); exit(1); }
	for (size_t i = 0; i < n; i++) {
		unsigned v;
		if (sscanf(s + 2 * i, "%2x", &v) != 1) { fprintf(stderr, "bad hex\n"); exit(1); }
		out[i] = (unsigned char)v;
	}
	return n;
}

static void put(const unsigned char *b, size_t n) {
	for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
	printf("\n");
}

int main(int argc, char **argv) {
	if (argc != 7) { fprintf(stderr, "usage\n"); return 1; }
	unsigned logn = (unsigned)atoi(argv[1]);
	static unsigned char kseed[4096], ctx[256], hv[65536], sseed[4096];
	size_t kseed_len = unhex(argv[2], kseed, sizeof kseed);
	size_t ctx_len = unhex(argv[3], ctx, sizeof ctx);
	size_t hv_len = unhex(argv[5], hv, sizeof hv);
	size_t sseed_len = unhex(argv[6], sseed, sizeof sseed);
	const char *mode = argv[4];
	const char *id;
	if (!strcmp(mode, "raw") || !strcmp(mode, "extmu")) id = FNDSA_HASH_ID_RAW;
	else if (!strcmp(mode, "sha256")) id = FNDSA_HASH_ID_SHA256;
	else if (!strcmp(mode, "sha512")) id = FNDSA_HASH_ID_SHA512;
	else if (!strcmp(mode, "sha3_256")) id = FNDSA_HASH_ID_SHA3_256;
	else if (!strcmp(mode, "sha3_512")) id = FNDSA_HASH_ID_SHA3_512;
	else { fprintf(stderr, "bad mode\n"); return 1; }

	size_t sk_len = FNDSA_SIGN_KEY_SIZE(logn);
	size_t vk_len = FNDSA_VRFY_KEY_SIZE(logn);
	size_t sig_len = FNDSA_SIGNATURE_SIZE(logn);
	unsigned char *sk = malloc(sk_len), *vk = malloc(vk_len), *sig = malloc(sig_len);
	fndsa_keygen_seeded(logn, kseed, kseed_len, sk, vk);

	unsigned char hvk[64], mu[64];
	fndsa_hashed_vrfykey_from_vrfykey(hvk, vk, vk_len);
	if (!fndsa_compute_mu(mu, hvk, ctx, ctx_len, id, hv, hv_len)) {
		fprintf(stderr, "compute_mu failed\n"); return 1;
	}
	size_t r;
	if (!strcmp(mode, "extmu")) {
		r = fndsa_sign_seeded(sk, sk_len, NULL, 0, FNDSA_HASH_ID_EXTMU,
			mu, 64, sseed, sseed_len, sig, sig_len);
	} else {
		r = fndsa_sign_seeded(sk, sk_len, ctx, ctx_len, id,
			hv, hv_len, sseed, sseed_len, sig, sig_len);
	}
	if (r != sig_len) { fprintf(stderr, "sign failed\n"); return 1; }
	put(sk, sk_len);
	put(vk, vk_len);
	put(mu, 64);
	put(sig, sig_len);
	return 0;
}
