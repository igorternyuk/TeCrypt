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

QByteArray TeCypher::enryptRSA(RSA *key, QByteArray &data, bool isPublic)
{
    QByteArray buffer;
    int dataSize = data.length();
    const unsigned char* str = (const unsigned char*)data.constData();
    int rsaKeySize = RSA_size(key);

    unsigned char* encryptedData = (unsigned char*)malloc(rsaKeySize);
    int resultLen = -1;
    if(isPublic)
    {
        resultLen = RSA_public_encrypt(dataSize, str, encryptedData, key, PADDING);
    }
    else
    {
        resultLen = RSA_private_encrypt(dataSize, str, encryptedData, key, PADDING);
    }
    //int resultLen = RSA_public_encrypt(dataSize, str, encryptedData, key, PADDING);
    //int resultLen = RSA_private_encrypt(dataSize, str, encryptedData, key, PADDING);
    if(resultLen == -1)
    {
        qCritical() << "Could not encrypt: " << ERR_error_string(ERR_get_error(), NULL);
        return buffer;
    }
    buffer = QByteArray(reinterpret_cast<char*>(encryptedData), resultLen);
    return buffer;
}

QByteArray TeCypher::decryptRSA(RSA *key, QByteArray &data, bool isPrivate)
{
    QByteArray buffer;
    const unsigned char* encyptedData = (const unsigned char*)data.constData();
    int rsaKeyLen = RSA_size(key);
    unsigned char* decryptedData = (unsigned char*)malloc(rsaKeyLen);
    int resultLen = -1;
    if(isPrivate)
    {
        resultLen = RSA_private_decrypt(rsaKeyLen, encyptedData, decryptedData, key, PADDING);
    }
    else
    {
        resultLen = RSA_public_decrypt(rsaKeyLen, encyptedData, decryptedData, key, PADDING);
    }
    if(resultLen == -1)
    {
        qCritical() << "Could not decrypt: " << ERR_error_string(ERR_get_error(), NULL);
        return buffer;
    }
    buffer = QByteArray::fromRawData((const char*)decryptedData, resultLen);
    free(decryptedData);
    return buffer;
}

QByteArray TeCypher::encryptAES(QByteArray &passphrase, QByteArray &data)
{
    QByteArray salz = this->randomBytes(SALT_SIZE);
    const int rounds = ROUNDS;
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    const unsigned char* salt = (const unsigned char*)salz.constData();
    const unsigned char* password = (const unsigned char*)passphrase.constData();

    //Create the key and the initialization vector(iv) based on the passphrase and the salt
    int keySize = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, password,
                           passphrase.length(), rounds, key, iv);

    if(keySize != KEY_SIZE)
    {
        qCritical() << "EVP_BytesToKey() error: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if(!EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(),
                          NULL, key, iv))
    {
        qCritical() << "EVP_EncryptInit_ex failed: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    char *input = data.data();
    int len = data.size();
    //char *out;
    int c_len = len + AES_BLOCK_SIZE;
    int f_len = 0;
    unsigned char* cipher_text = (unsigned char* )malloc(c_len);

    //Start enctyption egine
    if(!EVP_EncryptInit_ex(&ctx, NULL, NULL, NULL, NULL))
    {
        qCritical() << "EVP_EncryptInit_ex failed: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    if(!EVP_EncryptUpdate(&ctx, cipher_text, &c_len, (unsigned char*)input, len))
    {
        qCritical() << "EVP_EncodeUpdate failed: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    if(!EVP_EncryptFinal(&ctx, cipher_text + c_len, &f_len))
    {
        qCritical() << "EVP_EncryptFinal failed: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    len = c_len + f_len;
    EVP_CIPHER_CTX_cipher(&ctx);

    QByteArray encryptedMessage = QByteArray(reinterpret_cast<char*>(cipher_text), len);
    QByteArray finished;
    finished.append("Salted__");
    finished.append(salz);
    finished.append(encryptedMessage);
    EVP_CIPHER_CTX_cleanup(&ctx);
    free(cipher_text);
    return finished;
}

QByteArray TeCypher::decryptAES(QByteArray &passphrase, QByteArray &data)
{
    QByteArray salz = data.mid(0, SALT_SIZE);
    if(QString(data.mid(0, SALT_SIZE)) == "Salted__")
    {
        salz = data.mid(SALT_SIZE, SALT_SIZE);
        data = data.mid(2 * SALT_SIZE);
    }
    else
    {
        qWarning() << "Could not load salt from data!";
        salz = this->randomBytes(SALT_SIZE);
    }

    const int rounds = ROUNDS;
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    const unsigned char* salt = (const unsigned char*)salz.constData();
    const unsigned char* password = (const unsigned char*)passphrase.constData();

    int keySize = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, password,
                           passphrase.length(), rounds, key, iv);

    if(keySize != KEY_SIZE)
    {
        qCritical() << "EVP_BytesToKey() error: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if(!EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        qCritical() << "EVP_DecryptInit_ex failed: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    char* input = data.data();
    int len = data.size();
    //char *out;
    int p_len = len, f_len = 0;
    //f_len - final text length
    //p_len = decrypted plain text length
    unsigned char* plain_text = (unsigned char*)malloc(p_len + AES_BLOCK_SIZE);

    if(!EVP_DecryptUpdate(&ctx, plain_text, &p_len, (unsigned char*)input, len))
    {
        qCritical() << "EVP_DecryptUpdate: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    if(!EVP_DecryptFinal(&ctx, plain_text + p_len, &f_len))
    {
        qCritical() << "EVP_DecryptFinal: " <<
                       ERR_error_string(ERR_get_error(), NULL);
        return QByteArray();
    }

    len = p_len + f_len;
    //out = (char*)plain_text;
    EVP_CIPHER_CTX_cleanup(&ctx);

    QByteArray decryptedMessage = QByteArray(reinterpret_cast<char*>(plain_text), len);
    free(plain_text);
    return decryptedMessage;
}

QByteArray TeCypher::randomBytes(int size)
{
    unsigned char buf[size];
    RAND_bytes(buf, size);
    QByteArray array = QByteArray(reinterpret_cast<char*>(buf), size);
    return array;
}

void TeCypher::freeRSAKey(RSA *key)
{
    RSA_free(key);
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
    QFile fo(filename);
    if(!fo.open(QFile::WriteOnly))
    {
        qCritical() << fo.errorString();
        return;
    }
    fo.write(data);
    fo.close();
}
