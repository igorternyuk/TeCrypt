#include "tecypher.hpp"

#include <QDebug>

TeCypher::TeCypher(QObject *parent):
    QObject(parent)
{
    initialize();
}

TeCypher::~TeCypher()
{
    finalize();
}

RSA *TeCypher::getPublicKey(QByteArray &data)
{
    const char* publicKeyStr = data.constData();
    qDebug() << publicKeyStr;
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if(!rsaPubKey)
    {
        qCritical() << "Could not load the public key "
                    << ERR_error_string(ERR_get_error(), NULL);
    }
    BIO_free(bio);
    return rsaPubKey;
}

RSA *TeCypher::getPublicKey(QString &filename)
{
    QByteArray byteArray = readFile(filename);
    return this->getPublicKey(byteArray);
}

RSA *TeCypher::getPrivateKey(QByteArray &data)
{
    const char* privateKeyStr = data.constData();
    BIO* bio = BIO_new_mem_buf((void*)privateKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if(!rsaPrivKey)
    {
        qCritical() << "Could not load the private key "
                    << ERR_error_string(ERR_get_error(), NULL);
    }
    BIO_free(bio);
    return rsaPrivKey;
}

RSA *TeCypher::getPrivateKey(QString &filename)
{
    QByteArray byteArray = readFile(filename);
    return this->getPrivateKey(byteArray);
}

QByteArray TeCypher::enryptRSA(RSA *key, QByteArray &data)
{
    QByteArray buffer;
    int dataSize = data.length();
    const unsigned char* str = (const unsigned char*)data.constData();
    int rsaKeySize = RSA_size(key);

    unsigned char* encryptedData = (unsigned char*)malloc(rsaKeySize);
    int resultLen = RSA_public_encrypt(dataSize, str, encryptedData, key, PADDING);
    if(resultLen == -1)
    {
        qCritical() << "Could not encrypt: " << ERR_error_string(ERR_get_error(), NULL);
        return buffer;
    }
    buffer = QByteArray(reinterpret_cast<char*>(encryptedData), resultLen);
    return buffer;
}

QByteArray TeCypher::decryptRSA(RSA *key, QByteArray &data)
{
    QByteArray buffer;
    const unsigned char* encyptedData = (const unsigned char*)data.constData();
    int rsaKeyLen = RSA_size(key);
    unsigned char* decryptedData = (unsigned char*)malloc(rsaKeyLen);
    int resultLen = RSA_private_decrypt(rsaKeyLen, encyptedData, decryptedData, key, PADDING);
    if(resultLen == -1)
    {
        qCritical() << "Could not decrypt: " << ERR_error_string(ERR_get_error(), NULL);
        return buffer;
    }
    buffer = QByteArray::fromRawData((const char*)decryptedData, resultLen);
    return buffer;
}

QByteArray TeCypher::encryptAES(QByteArray &passphrase, QByteArray &data)
{

}

QByteArray TeCypher::decryptAES(QByteArray &passphrase, QByteArray &data)
{

}

QByteArray TeCypher::randomBytes(int size)
{

}

void TeCypher::freeRSAKey(RSA *key)
{

}

void TeCypher::initialize()
{
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void TeCypher::finalize()
{
    EVP_cleanup();
    ERR_free_strings();
}

QByteArray TeCypher::readFile(const QString &filename)
{
    QByteArray byteArray;
    QFile fi(filename);
    if(!fi.open(QFile::ReadOnly))
    {
        qCritical() << fi.errorString();
        return byteArray;
    }
    byteArray = fi.readAll();
    fi.close();
    return byteArray;
}

void TeCypher::writeFile(const QString &filename, QByteArray &data)
{

}
