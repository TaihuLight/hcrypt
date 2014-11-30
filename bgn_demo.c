#include <stdio.h>
#include <gmp.h>
#include <pbc.h>

int main(void)
{
	mpz_t q, r, n;

	FILE *fp = fopen("bgn.key", "rw");

	mpz_init(q);
	mpz_init(r);
	mpz_init(n);

	pbc_mpz_randomb(q, 512);
	pbc_mpz_randomb(r, 512);
	mpz_nextprime(q, q);
	mpz_nextprime(r, r);
	mpz_mul(n, q, r);

	gmp_printf("q = %Zx\n", q);
	gmp_printf("r = %Zx\n", r);
	gmp_printf("n = %Zx\n", n);

	pbc_param_t param;
	pbc_param_init_a1_gen(param, n);
	pbc_param_out_str(stdout, param);
	gmp_printf("%Zx ", q);
	gmp_printf("%Zx ", r);
	gmp_printf("%Zx\n", n);

	pairing_t pairing;
	pairing_init_pbc_param(pairing, param);
	
	printf("pairing_is_symmetric: %d\n", pairing_is_symmetric(pairing));
	printf("pairing_length_in_bytes_G1            : %d\n", pairing_length_in_bytes_G1(pairing));	
	printf("pairing_length_in_bytes_x_only_G1     : %d\n", pairing_length_in_bytes_x_only_G1(pairing));
	printf("pairing_length_in_bytes_compressed_G1 : %d\n", pairing_length_in_bytes_compressed_G1(pairing));
	printf("pairing_length_in_bytes_x_only_G2     : %d\n", pairing_length_in_bytes_x_only_G2(pairing));
	printf("pairing_length_in_bytes_compressed_G2 : %d\n", pairing_length_in_bytes_compressed_G2(pairing));
	printf("pairing_length_in_bytes_GT            : %d\n", pairing_length_in_bytes_GT(pairing));
	printf("pairing_length_in_bytes_Zr            : %d\n", pairing_length_in_bytes_Zr(pairing));
	
	element_t P, Q;
	element_init_G1(P, pairing);
	element_init_G1(Q, pairing);

	element_random(P);
	element_random(Q);

	//element_out_str(stdout, 16, P);
	element_printf("P = %B\n", P);	
	element_printf("Q' = %B\n", Q);

	element_mul_mpz(Q, Q, r);
	element_printf("Q = [r]Q' = %B\n", Q);

	element_t R;
	element_init_G1(R, pairing);
	element_mul_mpz(R, Q, q);
	element_printf("[q]Q = %B\n", R);

	element_t t;
	element_init_Zr(t, pairing);
	element_random(t);

	element_t m;
	element_init_Zr(m, pairing);
	element_set_si(m, 7);	

	element_t C;
	element_init_G1(C, pairing);
	
	element_t tQ;
	element_init_G1(tQ, pairing);
	element_mul(tQ, Q, t);
	
	element_t mP;
	element_init_G1(mP, pairing);
	element_mul(mP, P, m);
	element_add(C, mP, tQ);
	
	element_printf("C = %B\n", C);

	element_mul_mpz(C, C, q);
	element_printf("qC = %B\n", C);
	

	element_t qP;
	element_init_G1(qP, pairing);
	element_mul_mpz(qP, P, q);
	element_mul(qP, qP, m);
	element_printf("C' = %B\n", qP);	
		
	element_add(C, C, qP);

	return 0;
}
