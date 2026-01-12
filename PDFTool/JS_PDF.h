#ifndef JS_PDF_H
#define JS_PDF_H

#include <iostream>
#include "openssl/bio.h"
#include "js_bin.h"

#define INPUT_PDF  "D:/mywork/temp/Hello.pdf"
#define TEMP_PDF   "D:/mywork/temp/Hello_temp.pdf"
#define OUTPUT_PDF "D:/mywork/temp/Hello_signed.pdf"
#define ENC_PDF     "D:/mywork/temp/Hello_enc.pdf"
#define DEC_PDF     "D:/mywork/temp/Hello_dec.pdf"

#define CERT_FILE  "D:/mywork/temp/CN=SSL_Server,C=kr.crt"
#define KEY_FILE   "D:/mywork/temp/PrivateKey.pem"

int JS_PDF_extend_c( const char *pPDFPath, int *pnPages );
int JS_PDF_process( const char* whoami, char const* infile, std::string outprefix );


typedef struct {
    long range[4];
    long contents_start;
    long contents_end;
} ByteRangeInfo;

void add_signature_field(const char* in_pdf, const char* out_pdf);
void add_signature_field_c(const char* in_pdf, const char* out_pdf);
void add_signature_field_c2(const char* in_pdf, BIN *pOut );

int calculate_byte_range( const char* pdf_path, ByteRangeInfo* info);
int calculate_byte_range2( const BIN *pPDF, ByteRangeInfo* info);

int apply_byte_range( const char* pdf_path, const ByteRangeInfo* info );
int apply_byte_range2( BIN *pPDF, const ByteRangeInfo* info );

int apply_contents_signature( const char* pdf_path, const unsigned char* pkcs7_der, size_t pkcs7_der_len);
int apply_contents_signature2( BIN *pPDF, const unsigned char* pkcs7_der, size_t pkcs7_der_len);


void bin_to_hex( const unsigned char* bin, size_t bin_len, char* hex_out );

BIO* create_pdf_data_bio(const char* pdf_path,long start1,long len1,long start2,long len2);
BIO* create_pdf_data_bio2(const BIN *pPDF,long start1,long len1,long start2,long len2);


int create_pkcs7_signature(
    const char* pdf_path,
    long* byte_range,          // [0, len1, start2, len2]
    const char* cert_path,
    const char* key_path,
    const char* ca_chain_path, // NULL 가능
    unsigned char** out_der,
    size_t* out_der_len);

int create_pkcs7_signature2(
    const BIN *pPDF,
    long* byte_range,          // [0, len1, start2, len2]
    const char* cert_path,
    const char* key_path,
    const char* ca_chain_path, // NULL 가능
    unsigned char** out_der,
    size_t* out_der_len);

BIO* create_pdf_data_bio_for_verify(
    const char* pdf_path,
    long* byte_range   // [0, len1, start2, len2]
    );

BIO* create_pdf_data_bio_for_verify2(
    const BIN *pPDF,
    long* byte_range   // [0, len1, start2, len2]
    );

int verify_pkcs7_signature(
    const char* pdf_path,
    long* byte_range,
    const unsigned char* pkcs7_der,
    size_t pkcs7_der_len,
    const char* cert_path,
    const char* ca_bundle_path   // 시스템 CA or custom CA
    );

int verify_pkcs7_signature2(
    const BIN *pPDF,
    long* byte_range,
    const unsigned char* pkcs7_der,
    size_t pkcs7_der_len,
    const char* cert_path,
    const char* ca_bundle_path   // 시스템 CA or custom CA
    );

int extract_pkcs7_der_from_pdf(const char* pdf_path,unsigned char** out_der,size_t* out_der_len);
int extract_pkcs7_der_from_pdf2(const BIN* pPDF, BIN* pCMS );

int write_pdf( const BIN *pPDF, const char *out_file, const char *pPassword );

int pdf_encrypt( const char* pdf_path, const char* enc_path );
int pdf_decrypt( const char* enc_path, const char* pdf_path );

int pdf_encrypt_c( const char* pdf_path, const char* enc_path, const char *password );
int pdf_decrypt_c( const char* in_pdf, const char *password, const char* out_pdf  );

#endif // JS_PDF_H
