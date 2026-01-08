#ifndef JS_PDF_H
#define JS_PDF_H

#include <iostream>
#include "openssl/bio.h"

#define INPUT_PDF  "D:/mywork/temp/Hello.pdf"
#define TEMP_PDF   "D:/mywork/temp/Hello_temp.pdf"
#define OUTPUT_PDF "D:/mywork/temp/Hello_signed.pdf"

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

int calculate_byte_range( const char* pdf_path, ByteRangeInfo* info);
int apply_byte_range( const char* pdf_path, const ByteRangeInfo* info );
int apply_contents_signature( const char* pdf_path, const unsigned char* pkcs7_der, size_t pkcs7_der_len);
void bin_to_hex( const unsigned char* bin, size_t bin_len, char* hex_out );
BIO* create_pdf_data_bio(const char* pdf_path,long start1,long len1,long start2,long len2);
int create_pkcs7_signature(
    const char* pdf_path,
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

int verify_pkcs7_signature(
    const char* pdf_path,
    long* byte_range,
    const unsigned char* pkcs7_der,
    size_t pkcs7_der_len,
    const char* cert_path,
    const char* ca_bundle_path   // 시스템 CA or custom CA
    );

int extract_pkcs7_der_from_pdf(const char* pdf_path,unsigned char** out_der,size_t* out_der_len);

#endif // JS_PDF_H
