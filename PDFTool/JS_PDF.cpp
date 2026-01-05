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

#define SIGNATURE_MAX_LEN 8192   // ★ 매우 중요 (부족하면 서명 실패)

void create_unsigned_pdf(const char* in, const char* out) {
    QPDF pdf;
    pdf.processFile(in);

    QPDFObjectHandle sig =
        QPDFObjectHandle::parse(
            "<< /Type /Sig "
            "/Filter /Adobe.PPKLite "
            "/SubFilter /adbe.pkcs7.detached "
            "/ByteRange [0 0 0 0] "
            "/Contents <0000000000000000000000000000000000000000> "
            ">>"
            );

    QPDFObjectHandle annot =
        QPDFObjectHandle::parse(
            "<< /Type /Annot "
            "/Subtype /Widget "
            "/FT /Sig "
            "/Rect [0 0 0 0] "
            "/V " + sig.unparse() + " >>"
            );

    QPDFObjectHandle page = pdf.getAllPages().at(0);
    page.getKey("/Annots").appendItem(annot);

    QPDFWriter writer(pdf, out);
    writer.write();
}

unsigned char* cms_sign(
    const unsigned char* data,
    size_t data_len,
    const char* cert_file,
    const char* key_file,
    size_t* out_len
    ) {
    BIO *data_bio = BIO_new_mem_buf(data, data_len);
    BIO *out = BIO_new(BIO_s_mem());

    FILE* f = fopen(cert_file, "r");
    if( f == NULL ) return NULL;

    X509* cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    f = fopen(key_file, "r");
    if( f == NULL ) return NULL;

    EVP_PKEY* pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    CMS_ContentInfo* cms = CMS_sign(
        cert,
        pkey,
        NULL,
        data_bio,
        CMS_BINARY | CMS_DETACHED
        );

    i2d_CMS_bio(out, cms);

    *out_len = BIO_pending(out);
    unsigned char* buf = (unsigned char *)JS_malloc(*out_len);
    BIO_read(out, buf, *out_len);

    CMS_ContentInfo_free(cms);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    BIO_free(data_bio);
    BIO_free(out);

    return buf;
}

void sign_pdf(
    const char* unsigned_pdf,
    const char* signed_pdf,
    const char* cert,
    const char* key
    ) {
    FILE* f = fopen(unsigned_pdf, "rb");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);

    unsigned char* pdf = (unsigned char *)JS_malloc(len);
    fread(pdf, 1, len, f);
    fclose(f);

    char* contents_pos = strstr((char*)pdf, "/Contents <");
    char* hex_start = contents_pos + strlen("/Contents <");
    char* hex_end = strchr(hex_start, '>');

    size_t contents_offset = hex_start - (char*)pdf;
    size_t contents_len = hex_end - hex_start;

    char byte_range[256];
    size_t br1 = 0;
    size_t br2 = contents_offset;
    size_t br3 = contents_offset + contents_len + 1;
    size_t br4 = len - br3;

    snprintf(byte_range, sizeof(byte_range),
             "/ByteRange [0 %zu %zu %zu]",
             br2, br3, br4
             );

    char* br_pos = strstr((char*)pdf, "/ByteRange");
    memcpy(br_pos, byte_range, strlen(byte_range));

    // 서명 대상 데이터 생성
    unsigned char* sign_data = (unsigned char *)JS_malloc(br2 + br4);
    memcpy(sign_data, pdf, br2);
    memcpy(sign_data + br2, pdf + br3, br4);

    size_t sig_len;
    unsigned char* sig = cms_sign(sign_data, br2 + br4, cert, key, &sig_len);
    if( sig == NULL ) return;

    // HEX 인코딩
    for (size_t i = 0; i < sig_len; i++) {
        sprintf(hex_start + (i * 2), "%02X", sig[i]);
    }

    FILE* out = fopen(signed_pdf, "wb");
    fwrite(pdf, 1, len, out);
    fclose(out);

    free(sig);
    free(sign_data);
    free(pdf);
}

unsigned char* sign_data_pkcs7(
    const unsigned char* data,
    size_t data_len,
    const char* cert_path,
    const char* key_path,
    size_t* sig_len
    ) {
    BIO *data_bio = NULL, *out = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    PKCS7 *p7 = NULL;
    unsigned char *sig = NULL;

    OpenSSL_add_all_algorithms();

    data_bio = BIO_new_mem_buf(data, data_len);

    FILE* f = fopen(cert_path, "r");
    cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);

    f = fopen(key_path, "r");
    pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);

    p7 = PKCS7_sign(
        cert,
        pkey,
        NULL,
        data_bio,
        PKCS7_BINARY | PKCS7_DETACHED
        );

    out = BIO_new(BIO_s_mem());
    i2d_PKCS7_bio(out, p7);

    *sig_len = BIO_pending(out);
    sig = (unsigned char *)JS_malloc(*sig_len);
    BIO_read(out, sig, *sig_len);

    BIO_free(data_bio);
    BIO_free(out);
    PKCS7_free(p7);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return sig;
}


void PDF_Test()
{
    create_unsigned_pdf("input.pdf", "unsigned.pdf");

    sign_pdf(
        "unsigned.pdf",
        "signed.pdf",
        "cert.pem",
        "key.pem"
        );
}


unsigned char hex_to_byte(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    return 0;
}

unsigned char* hex_decode(const char* hex, size_t len, size_t* out_len) {
    *out_len = len / 2;
    unsigned char* out = (unsigned char *)JS_malloc(*out_len);

    for (size_t i = 0; i < *out_len; i++) {
        out[i] = (hex_to_byte(hex[i * 2]) << 4)
        |  hex_to_byte(hex[i * 2 + 1]);
    }
    return out;
}

int extract_signature(
    const unsigned char* pdf,
    size_t pdf_len,
    size_t br[4],
    unsigned char** sig,
    size_t* sig_len
    ) {
    char* br_pos = strstr((char*)pdf, "/ByteRange [");
    if (!br_pos) return 0;

    sscanf(br_pos, "/ByteRange [%zu %zu %zu %zu]",
           &br[0], &br[1], &br[2], &br[3]);

    char* cont_pos = strstr((char*)pdf, "/Contents <");
    if (!cont_pos) return 0;

    char* hex_start = cont_pos + strlen("/Contents <");
    char* hex_end = strchr(hex_start, '>');

    *sig = hex_decode(hex_start, hex_end - hex_start, sig_len);
    return 1;
}

unsigned char* build_signed_data(
    const unsigned char* pdf,
    size_t br[4],
    size_t* out_len
    ) {
    *out_len = br[1] + br[3];
    unsigned char* data = (unsigned char *)JS_malloc(*out_len);

    memcpy(data, pdf + br[0], br[1]);
    memcpy(data + br[1], pdf + br[2], br[3]);

    return data;
}

int verify_cms(
    unsigned char* sig,
    size_t sig_len,
    unsigned char* data,
    size_t data_len,
    const char* ca_file   // NULL 가능
    ) {
    BIO* sig_bio = BIO_new_mem_buf(sig, sig_len);
    BIO* data_bio = BIO_new_mem_buf(data, data_len);

    CMS_ContentInfo* cms = d2i_CMS_bio(sig_bio, NULL);

    X509_STORE* store = NULL;
    if (ca_file) {
        store = X509_STORE_new();
        X509_STORE_load_locations(store, ca_file, NULL);
    }

    int ret = CMS_verify(
        cms,
        NULL,           // signers
        store,          // CA store (NULL = 서명 무결성만 검증)
        data_bio,
        NULL,
        CMS_BINARY
        );

    CMS_ContentInfo_free(cms);
    BIO_free(sig_bio);
    BIO_free(data_bio);
    if (store) X509_STORE_free(store);

    return ret;
}

int PDF_VerifyTest( int argc, char* argv[] )
{
    if (argc < 2) {
        printf("usage: verify_pdf signed.pdf [ca.pem]\n");
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);

    unsigned char* pdf = (unsigned char *)JS_malloc(len);
    fread(pdf, 1, len, f);
    fclose(f);

    size_t br[4];
    unsigned char* sig;
    size_t sig_len;

    if (!extract_signature(pdf, len, br, &sig, &sig_len)) {
        printf("❌ 서명 추출 실패\n");
        return 1;
    }

    size_t data_len;
    unsigned char* data = build_signed_data(pdf, br, &data_len);

    const char* ca = (argc >= 3) ? argv[2] : NULL;

    if (verify_cms(sig, sig_len, data, data_len, ca)) {
        printf("✅ PDF 서명 검증 성공\n");
    } else {
        printf("❌ PDF 서명 검증 실패\n");
    }

    free(sig);
    free(data);
    free(pdf);

    return 0;
}

#if 0
int test()
{
    // Step 1. QPDF로 PDF 로드
    QPDF pdf;
    pdf.processFile("unsigned.pdf");

    // Step 2. 서명 대상 ByteRange 계산
    auto signer = pdf.getSignatureHandler("Sig1");
    std::vector<QPDFObjectHandle> byteRange = signer.getByteRange();

    // Step 3. OpenSSL 서명 (EVP API)
    EVP_PKEY *pkey = loadPrivateKey("key.pem");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
    EVP_DigestSignUpdate(ctx, data, datalen);
    EVP_DigestSignFinal(ctx, signature, &siglen);

    // Step 4. CMS(PKCS#7) 래핑 후 /Contents 삽입
    signer.setContents(cms_der_bytes);

    // Step 5. 서명된 PDF 저장
    pdf.write("signed.pdf");
}
#endif
