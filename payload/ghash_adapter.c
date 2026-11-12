/* Original ABI adapter, MIT. Arithmetic: OpenSSL's ARM GHASH (see vendor). */
extern void gcm_gmult_4bit(void *,const unsigned long long *);
void skater_gmult(void *xi,const unsigned long long *source) {
    unsigned long long table[32];
    unsigned i;
    /* Stock C table: hi64,lo64. Little-endian ARM assembly: lo64,hi64. */
    for(i=0;i<16;i++) { table[2*i]=source[2*i+1];table[2*i+1]=source[2*i]; }
    gcm_gmult_4bit(xi,table);
}
