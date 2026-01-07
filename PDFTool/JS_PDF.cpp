#include "JS_PDF.h"
#include "qpdf/qpdf-c.h"
#include "js_bin.h"

#include <qpdf/QIntC.hh>
#include <qpdf/QPDF.hh>
#include <qpdf/QPDFPageDocumentHelper.hh>
#include <qpdf/QPDFWriter.hh>
#include <qpdf/QUtil.hh>

#include "openssl/pkcs7.h"
#include "openssl/cms.h"
#include "openssl/pem.h"

#include <qpdf/QPDF.hh>
#include <qpdf/QPDFObjectHandle.hh>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <fstream>
#include <vector>
#include <string>
#include <iostream>

int
numPages(std::shared_ptr<QPDF> qpdf)
{
    return qpdf->getRoot().getKey("/Pages").getKey("/Count").getIntValueAsInt();
}

// Now we define the glue that makes our function callable using the C API.

// This is the C++ implementation of the C function.
QPDF_ERROR_CODE
num_pages(qpdf_data qc, int* npages)
{
    // Call qpdf_c_wrap to convert any exception our function might through to a QPDF_ERROR_CODE
    // and attach it to the qpdf_data object in the same way as other functions in the C API.
    return qpdf_c_wrap(qc, [&qc, &npages]() { *npages = numPages(qpdf_c_get_qpdf(qc)); });
}

static char const* whoami = 0;

int JS_PDF_extend_c( const char *pPDFPath,  int *pnPages  )
{
    const char* infile = NULL;
    qpdf_data qpdf = qpdf_init();
    int warnings = 0;
    int errors = 0;
    char* p = NULL;

    infile = pPDFPath;

    if ((qpdf_read(qpdf, infile, NULL) & QPDF_ERRORS) == 0) {
        int npages;
        if ((num_pages(qpdf, &npages) & QPDF_ERRORS) == 0) {
            printf("num pages = %d\n", npages);
            *pnPages = npages;
        }
    }
    if (qpdf_more_warnings(qpdf)) {
        warnings = 1;
    }
    if (qpdf_has_error(qpdf)) {
        errors = 1;
        printf("error: %s\n", qpdf_get_error_full_text(qpdf, qpdf_get_error(qpdf)));
    }
    qpdf_cleanup(&qpdf);
    if (errors) {
        return 2;
    } else if (warnings) {
        return 3;
    }

    return 0;
}

static bool static_id = false;

int JS_PDF_process( const char* whoami, char const* infile, std::string outprefix )
{
    QPDF inpdf;
    inpdf.processFile(infile);
    std::vector<QPDFPageObjectHelper> pages = QPDFPageDocumentHelper(inpdf).getAllPages();
    int pageno_len = QIntC::to_int(std::to_string(pages.size()).length());
    int pageno = 0;
    for (auto& page: pages) {
        std::string outfile = outprefix + QUtil::int_to_string(++pageno, pageno_len) + ".pdf";
        QPDF outpdf;
        outpdf.emptyPDF();
        QPDFPageDocumentHelper(outpdf).addPage(page, false);
        QPDFWriter outpdfw(outpdf, outfile.c_str());
        if (static_id) {
            // For the test suite, uncompress streams and use static IDs.
            outpdfw.setStaticID(true); // for testing only
            outpdfw.setStreamDataMode(qpdf_s_uncompress);
        }
        outpdfw.write();
    }

    return 0;
}

void add_signature_field(const char* in_pdf, const char* out_pdf)
{
    QPDF pdf;
    pdf.processFile(in_pdf);

    /* ===============================
       1. AcroForm 확보
       =============================== */
    QPDFObjectHandle root = pdf.getRoot();
    QPDFObjectHandle acroform;

    if (!root.hasKey("/AcroForm")) {
        acroform = QPDFObjectHandle::newDictionary();
        acroform.replaceKey("/Fields", QPDFObjectHandle::newArray());
        root.replaceKey("/AcroForm", acroform);
    } else {
        acroform = root.getKey("/AcroForm");
    }

    QPDFObjectHandle fields = acroform.getKey("/Fields");

    /* ===============================
       2. Signature Dictionary 생성
       =============================== */
    QPDFObjectHandle sig_dict = QPDFObjectHandle::newDictionary();
    sig_dict.replaceKey("/Type", QPDFObjectHandle::newName("/Sig"));
    sig_dict.replaceKey("/Filter", QPDFObjectHandle::newName("/Adobe.PPKLite"));
    sig_dict.replaceKey("/SubFilter", QPDFObjectHandle::newName("/adbe.pkcs7.detached"));

    /* ByteRange placeholder */

    QPDFObjectHandle byte_range = QPDFObjectHandle::newArray();
    byte_range.appendItem(QPDFObjectHandle::newInteger(0));
    byte_range.appendItem(QPDFObjectHandle::newInteger(11111111));
    byte_range.appendItem(QPDFObjectHandle::newInteger(22222222));
    byte_range.appendItem(QPDFObjectHandle::newInteger(33333333));
    sig_dict.replaceKey("/ByteRange", byte_range);

    /* ===============================
       3. Contents Placeholder
       =============================== */
    const int contents_size = 16384; // 16KB
//    std::string zeros(contents_size * 2, '0' ); // HEX 문자열
    std::string zeros(contents_size * 2, 0x00 ); // HEX 문자열

    QPDFObjectHandle contents = QPDFObjectHandle::newString(zeros);

//    contents.setHexString(true);
    sig_dict.replaceKey("/Contents", contents);

    /* 서명 시각 */
    sig_dict.replaceKey("/M",
                        QPDFObjectHandle::newString("D:20260106120000+09'00'"));

    QPDFObjectHandle sig_dict_indirect =
        pdf.makeIndirectObject(sig_dict);

    /* ===============================
       4. Signature Field 생성
       =============================== */
    QPDFObjectHandle sig_field = QPDFObjectHandle::newDictionary();
    sig_field.replaceKey("/Type", QPDFObjectHandle::newName("/Annot"));
    sig_field.replaceKey("/Subtype", QPDFObjectHandle::newName("/Widget"));
    sig_field.replaceKey("/FT", QPDFObjectHandle::newName("/Sig"));
    sig_field.replaceKey("/T", QPDFObjectHandle::newString("Signature1"));
    sig_field.replaceKey("/V", sig_dict_indirect);
    sig_field.replaceKey("/F", QPDFObjectHandle::newInteger(4));

    /* 위치 (보이지 않게 하려면 0,0,0,0) */
    QPDFObjectHandle rect = QPDFObjectHandle::newArray();
    rect.appendItem(QPDFObjectHandle::newInteger(0));
    rect.appendItem(QPDFObjectHandle::newInteger(0));
    rect.appendItem(QPDFObjectHandle::newInteger(0));
    rect.appendItem(QPDFObjectHandle::newInteger(0));
    sig_field.replaceKey("/Rect", rect);

    QPDFObjectHandle sig_field_indirect =
        pdf.makeIndirectObject(sig_field);

    fields.appendItem(sig_field_indirect);

    /* ===============================
       5. 페이지에 Widget Annotation 추가
       =============================== */
    std::vector<QPDFObjectHandle> pages = pdf.getAllPages();
    if (!pages.empty()) {
        QPDFObjectHandle page = pages[0];

        if (!page.hasKey("/Annots")) {
            page.replaceKey("/Annots", QPDFObjectHandle::newArray());
        }
        page.getKey("/Annots").appendItem(sig_field_indirect);
    }

    /* ===============================
       6. Incremental Update 저장
       =============================== */
    QPDFWriter writer(pdf, out_pdf);
//    writer.setStaticID(true);
//    writer.setIncremental(true);

    writer.write();
}


int calculate_byte_range( const char* pdf_path, ByteRangeInfo* info)
{
    FILE* fp = fopen(pdf_path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    unsigned char* buf = (unsigned char*)malloc(file_size);
    if (!buf) {
        fclose(fp);
        return -2;
    }

    fread(buf, 1, file_size, fp);
    fclose(fp);

    /* "/Contents" 문자열 검색 */
    const char* key = "/Contents";
    unsigned char* p = buf;
    unsigned char* end = buf + file_size;

    unsigned char* contents_pos = NULL;

    while (p < end - strlen(key)) {
        if (memcmp(p, key, strlen(key)) == 0) {
            contents_pos = p;
            break;
        }
        p++;
    }

    if (!contents_pos) {
        free(buf);
        return -3;
    }

    /* '<' 위치 찾기 */
    unsigned char* hex_start = NULL;
    p = contents_pos;

    while (p < end) {
        if (*p == '<') {
            hex_start = p;
            break;
        }
        p++;
    }

    if (!hex_start) {
        free(buf);
        return -4;
    }

    /* '>' 위치 찾기 */
    unsigned char* hex_end = NULL;
    p = hex_start + 1;

    while (p < end) {
        if (*p == '>') {
            hex_end = p;
            break;
        }
        p++;
    }

    if (!hex_end) {
        free(buf);
        return -5;
    }

    info->contents_start = hex_start - buf;
    info->contents_end   = hex_end - buf + 1; // '>' 포함

    long contents_len = info->contents_end - info->contents_start;

    /* ByteRange 계산 */
    info->range[0] = 0;
    info->range[1] = info->contents_start;
    info->range[2] = info->contents_start + contents_len;
    info->range[3] = file_size - info->range[2];

    free(buf);
    return 0;
}

int apply_byte_range( const char* pdf_path, const ByteRangeInfo* info )
{
    FILE* fp = fopen(pdf_path, "rb+");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    unsigned char* buf = (unsigned char*)malloc(file_size);
    if (!buf) {
        fclose(fp);
        return -2;
    }

    fread(buf, 1, file_size, fp);

    /* "/ByteRange" 찾기 */
    const char* key = "/ByteRange";
    unsigned char* p = buf;
    unsigned char* end = buf + file_size;
    unsigned char* br_pos = NULL;

    while (p < end - strlen(key)) {
        if (memcmp(p, key, strlen(key)) == 0) {
            br_pos = p;
            break;
        }
        p++;
    }

    if (!br_pos) {
        free(buf);
        fclose(fp);
        return -3;
    }

    /* '[' 위치 */
    unsigned char* br_start = NULL;
    p = br_pos;
    while (p < end) {
        if (*p == '[') {
            br_start = p;
            break;
        }
        p++;
    }

    if (!br_start) {
        free(buf);
        fclose(fp);
        return -4;
    }

    /* ']' 위치 */
    unsigned char* br_end = NULL;
    p = br_start;
    while (p < end) {
        if (*p == ']') {
            br_end = p;
            break;
        }
        p++;
    }

    if (!br_end) {
        free(buf);
        fclose(fp);
        return -5;
    }

    long old_len = br_end - br_start + 1;

    /* 새 ByteRange 문자열 생성 */
    char new_br[256];
    snprintf(
        new_br,
        sizeof(new_br),
        "[%ld %ld %ld %ld]",
        info->range[0],
        info->range[1],
        info->range[2],
        info->range[3]
        );

    long new_len = strlen(new_br);

    if (new_len > old_len) {
        /* 길이 초과 → 절대 안 됨 */
        free(buf);
        fclose(fp);
        return -6;
    }

    /* 기존 영역 공백으로 초기화 */
    memset(br_start, ' ', old_len);

    /* ByteRange 덮어쓰기 */
    memcpy(br_start, new_br, new_len);

    /* 파일에 다시 기록 */
    rewind(fp);
    fwrite(buf, 1, file_size, fp);

    fflush(fp);
    fclose(fp);
    free(buf);

    return 0;
}

void bin_to_hex( const unsigned char* bin, size_t bin_len, char* hex_out )
{
    static const char* hex = "0123456789ABCDEF";
    for (size_t i = 0; i < bin_len; i++) {
        hex_out[i * 2]     = hex[(bin[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex[bin[i] & 0xF];
    }
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}


int hex_to_bin(
    const char* hex,
    size_t hex_len,
    unsigned char* out
    ) {
    if (hex_len % 2 != 0) return -1;

    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = hex_value(hex[i]);
        int lo = hex_value(hex[i + 1]);
        if (hi < 0 || lo < 0) return -2;
        out[i / 2] = (unsigned char)((hi << 4) | lo);
    }
    return (int)(hex_len / 2);
}


int apply_contents_signature( const char* pdf_path, const unsigned char* pkcs7_der, size_t pkcs7_der_len)
{
    FILE* fp = fopen(pdf_path, "rb+");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    unsigned char* buf = (unsigned char*)malloc(file_size);
    if (!buf) {
        fclose(fp);
        return -2;
    }

    fread(buf, 1, file_size, fp);

    /* "/Contents" 찾기 */
    const char* key = "/Contents";
    unsigned char* p = buf;
    unsigned char* end = buf + file_size;
    unsigned char* contents_pos = NULL;

    while (p < end - strlen(key)) {
        if (memcmp(p, key, strlen(key)) == 0) {
            contents_pos = p;
            break;
        }
        p++;
    }

    if (!contents_pos) {
        free(buf);
        fclose(fp);
        return -3;
    }

    /* '<' 위치 */
    unsigned char* hex_start = NULL;
    p = contents_pos;
    while (p < end) {
        if (*p == '<') {
            hex_start = p;
            break;
        }
        p++;
    }

    if (!hex_start) {
        free(buf);
        fclose(fp);
        return -4;
    }

    /* '>' 위치 */
    unsigned char* hex_end = NULL;
    p = hex_start + 1;
    while (p < end) {
        if (*p == '>') {
            hex_end = p;
            break;
        }
        p++;
    }

    if (!hex_end) {
        free(buf);
        fclose(fp);
        return -5;
    }

    long placeholder_len = hex_end - hex_start - 1; // HEX 영역만
    long required_len = pkcs7_der_len * 2;

    if (required_len > placeholder_len) {
        /* placeholder 부족 */
        free(buf);
        fclose(fp);
        return -6;
    }

    /* DER → HEX */
    char* hex_sig = (char*)malloc(required_len);
    if (!hex_sig) {
        free(buf);
        fclose(fp);
        return -7;
    }

    bin_to_hex(pkcs7_der, pkcs7_der_len, hex_sig);

    /* 기존 영역을 '0'으로 초기화 */
    memset(hex_start + 1, '0', placeholder_len);

    /* HEX 서명 덮어쓰기 */
    memcpy(hex_start + 1, hex_sig, required_len);

    /* 파일에 다시 기록 */
    rewind(fp);
    fwrite(buf, 1, file_size, fp);

    fflush(fp);
    fclose(fp);

    free(hex_sig);
    free(buf);

    return 0;
}

void print_openssl_error(void)
{
    ERR_print_errors_fp(stderr);
}

EVP_PKEY* load_private_key(const char* path)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) return NULL;

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

X509* load_certificate(const char* path)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) return NULL;

    X509* cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

STACK_OF(X509)* load_ca_chain(const char* path)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) return NULL;

    STACK_OF(X509)* chain = sk_X509_new_null();
    while (1) {
        X509* ca = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!ca) break;
        sk_X509_push(chain, ca);
    }
    fclose(fp);
    return chain;
}

BIO* create_pdf_data_bio(const char* pdf_path,long start1,long len1,long start2,long len2)
{
    FILE* fp = fopen(pdf_path, "rb");
    if (!fp) return NULL;

    BIO* bio = BIO_new(BIO_s_mem());

    unsigned char buffer[4096];
    size_t n;

    /* 첫 번째 구간 */
    fseek(fp, start1, SEEK_SET);
    long remaining = len1;
    while (remaining > 0) {
        size_t to_read = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;
        n = fread(buffer, 1, to_read, fp);
        if (n <= 0) break;
        BIO_write(bio, buffer, n);
        remaining -= n;
    }

    /* 두 번째 구간 */
    fseek(fp, start2, SEEK_SET);
    remaining = len2;
    while (remaining > 0) {
        size_t to_read = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;
        n = fread(buffer, 1, to_read, fp);
        if (n <= 0) break;
        BIO_write(bio, buffer, n);
        remaining -= n;
    }

    fclose(fp);
    return bio;
}

int create_pkcs7_signature(
    const char* pdf_path,
    long* byte_range,          // [0, len1, start2, len2]
    const char* cert_path,
    const char* key_path,
    const char* ca_chain_path, // NULL 가능
    unsigned char** out_der,
    size_t* out_der_len)
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY* pkey = load_private_key(key_path);
    X509* cert = load_certificate(cert_path);
    STACK_OF(X509)* ca_chain = NULL;

    if (!pkey || !cert) {
        print_openssl_error();
        return -1;
    }

    if (ca_chain_path) {
        ca_chain = load_ca_chain(ca_chain_path);
    }

    BIO* data_bio = create_pdf_data_bio(
        pdf_path,
        byte_range[0],
        byte_range[1],
        byte_range[2],
        byte_range[3]
        );

    if (!data_bio) {
        print_openssl_error();
        return -2;
    }

    /* 🔥 PKCS#7 서명 */
    PKCS7* p7 = PKCS7_sign(
        cert,
        pkey,
        ca_chain,
        data_bio,
        PKCS7_DETACHED | PKCS7_BINARY
        );

    if (!p7) {
        print_openssl_error();
        return -3;
    }

    /* DER 추출 */
    int len = i2d_PKCS7(p7, NULL);
    if (len <= 0) {
        print_openssl_error();
        return -4;
    }

    unsigned char* der = (unsigned char*)OPENSSL_malloc(len);
    unsigned char* p = der;

    i2d_PKCS7(p7, &p);

    *out_der = der;
    *out_der_len = len;

    /* 정리 */
    PKCS7_free(p7);
    BIO_free(data_bio);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    if (ca_chain) sk_X509_pop_free(ca_chain, X509_free);

    return 0;
}

PKCS7* load_pkcs7_from_der(
    const unsigned char* der,
    size_t der_len
    ) {
    const unsigned char* p = der;
    return d2i_PKCS7(NULL, &p, der_len);
}

BIO* create_pdf_data_bio_for_verify(
    const char* pdf_path,
    long* byte_range   // [0, len1, start2, len2]
    )
{
    FILE* fp = fopen(pdf_path, "rb");
    if (!fp) return NULL;

    BIO* bio = BIO_new(BIO_s_mem());
    unsigned char buffer[4096];
    size_t n;

    /* 첫 번째 영역 */
    fseek(fp, byte_range[0], SEEK_SET);
    long remaining = byte_range[1];
    while (remaining > 0) {
        size_t to_read = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;
        n = fread(buffer, 1, to_read, fp);
        if (n <= 0) break;
        BIO_write(bio, buffer, n);
        remaining -= n;
    }

    /* 두 번째 영역 */
    fseek(fp, byte_range[2], SEEK_SET);
    remaining = byte_range[3];
    while (remaining > 0) {
        size_t to_read = remaining > sizeof(buffer) ? sizeof(buffer) : remaining;
        n = fread(buffer, 1, to_read, fp);
        if (n <= 0) break;
        BIO_write(bio, buffer, n);
        remaining -= n;
    }

    fclose(fp);
    return bio;
}

X509_STORE* create_ca_store(const char* ca_bundle_path)
{
    X509_STORE* store = X509_STORE_new();
    if (!store) return NULL;

    if (X509_STORE_load_locations(store, ca_bundle_path, NULL) != 1) {
        X509_STORE_free(store);
        return NULL;
    }

    return store;
}

int extract_pkcs7_der_from_pdf(const char* pdf_path,unsigned char** out_der,size_t* out_der_len)
{
    FILE* fp = fopen(pdf_path, "rb");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    unsigned char* buf = (unsigned char*)malloc(file_size);
    if (!buf) {
        fclose(fp);
        return -2;
    }

    fread(buf, 1, file_size, fp);
    fclose(fp);

    /* "/Contents" 검색 */
    const char* key = "/Contents";
    unsigned char* p = buf;
    unsigned char* end = buf + file_size;
    unsigned char* contents_pos = NULL;

    while (p < end - strlen(key)) {
        if (memcmp(p, key, strlen(key)) == 0) {
            contents_pos = p;
            break;
        }
        p++;
    }

    if (!contents_pos) {
        free(buf);
        return -3;
    }

    /* '<' 찾기 */
    unsigned char* hex_start = NULL;
    p = contents_pos;
    while (p < end) {
        if (*p == '<') {
            hex_start = p + 1;
            break;
        }
        p++;
    }

    if (!hex_start) {
        free(buf);
        return -4;
    }

    /* '>' 찾기 */
    unsigned char* hex_end = NULL;
    p = hex_start;
    while (p < end) {
        if (*p == '>') {
            hex_end = p;
            break;
        }
        p++;
    }

    if (!hex_end) {
        free(buf);
        return -5;
    }

    size_t hex_len = hex_end - hex_start;

    /* 뒤쪽 00 패딩 제거 */
    while (hex_len >= 2 &&
           hex_start[hex_len - 1] == '0' &&
           hex_start[hex_len - 2] == '0') {
        hex_len -= 2;
    }

    unsigned char* der = (unsigned char*)malloc(hex_len / 2);
    if (!der) {
        free(buf);
        return -6;
    }

    int der_len = hex_to_bin((char*)hex_start, hex_len, der);
    if (der_len <= 0) {
        free(der);
        free(buf);
        return -7;
    }

    *out_der = der;
    *out_der_len = der_len;

    free(buf);
    return 0;
}


int verify_pkcs7_signature(
    const char* pdf_path,
    long* byte_range,
    const unsigned char* pkcs7_der,
    size_t pkcs7_der_len,
    const char* cert_path,
    const char* ca_bundle_path   // 시스템 CA or custom CA
    )
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int ret = -1;
    X509_STORE* store = NULL;
    STACK_OF(X509) *pSignerCerts = NULL;

    /* PKCS7 파싱 */
    PKCS7* p7 = load_pkcs7_from_der(pkcs7_der, pkcs7_der_len);
    if (!p7) {
        print_openssl_error();
        return -2;
    }

    /* ByteRange 데이터 */
    BIO* data_bio = create_pdf_data_bio_for_verify(pdf_path, byte_range);
    if (!data_bio) {
        PKCS7_free(p7);
        return -3;
    }

    /* CA Store */
    if( ca_bundle_path != NULL )
    {
        store = create_ca_store(ca_bundle_path);
        if (!store) {
            PKCS7_free(p7);
            BIO_free(data_bio);
            return -4;
        }
    }

    if( cert_path != NULL )
    {
        pSignerCerts = sk_X509_new_null();
        X509 *pXCert = load_certificate( cert_path );
        if( pXCert ) sk_X509_push( pSignerCerts, pXCert );
    }

    /*
     * PKCS7_verify flags
     *  - PKCS7_BINARY  : PDF는 항상 binary
     *  - PKCS7_NOINTERN: 내부 cert 외부에서 검증
     */
//    int flags = PKCS7_BINARY;
    int flags = PKCS7_BINARY | PKCS7_DETACHED | PKCS7_NOVERIFY;

    ret = PKCS7_verify(
        p7,
        pSignerCerts,          // 서명자 cert (NULL → 내부 cert 사용)
        store,         // 신뢰 CA
        data_bio,      // 원문 데이터
        NULL,          // output BIO (detached)
        flags
        );

    if (ret != 1) {
        print_openssl_error();
        ret = 0;   // 검증 실패
    } else {
        ret = 1;   // 검증 성공
    }

    /* 정리 */
    X509_STORE_free(store);
    BIO_free(data_bio);
    PKCS7_free(p7);
    if( pSignerCerts ) sk_X509_free( pSignerCerts );

    return ret;
}
