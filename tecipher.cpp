#include "tecipher.hpp"
#include <QFile>
#include <QDebug>

TeCipher::TeCipher(QObject *parent):
    QObject(parent)
{
    initialize();
}

TeCipher::~TeCipher()
{
    finalize();
}

bool TeCipher::loadPublicKeyByteArrayFromFile(const QString &pathToPublicKeyFile)
{
    QFile fi(pathToPublicKeyFile);
    if(!fi.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        mLastError.clear();
        mLastError.append("Could not open the public key file: ");
        mLastError.append(fi.errorString());
        qCritical() << mLastError;
        return false;
    }

    //qDebug() << "File " << pathToPublicKeyFile << " opened";
    mPublicKey = fi.readAll();
    //qDebug() << "Loaded public key:";
    //qDebug() << mPublicKey;
    fi.close();
    return true;
}

bool TeCipher::loadPrivateKeyByteArrayFromFile(const QString &pathToPrivateKeyFile)
{
    QFile fi(pathToPrivateKeyFile);
    if(!fi.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        mLastError = "Could not open the private key file: " + fi.errorString();
        qCritical() << mLastError;
        return false;
    }

    //qDebug() << "File " << pathToPrivateKeyFile << " opened";
    mPrivateKey = fi.readAll();
    //qDebug() << "Loaded private key:";
    //qDebug() << mPrivateKey;
    fi.close();
    return true;
}


RSA *TeCipher::getPublicRSAKey(QByteArray &data)
{
    const char* publicKeyStr = data.constData();
    //qDebug() << publicKeyStr;
    BIO* bio = BIO_new_mem_buf((void*)publicKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if(!rsaPubKey)
    {
        mLastError.clear();
        mLastError.append("Could not load the public key: ");
        mLastError.append(ERR_error_string(ERR_get_error(), NULL));
        qCritical() << mLastError;
    }
    BIO_free(bio);
    return rsaPubKey;
}

RSA *TeCipher::getPublicRSAKey(QString &filename)
{
    QByteArray byteArray = readFile(filename);
    return this->getPublicRSAKey(byteArray);
}

RSA *TeCipher::getPrivateRSAKey(QByteArray &data)
{
    const char* privateKeyStr = data.constData();
    //qDebug() << privateKeyStr;
    BIO* bio = BIO_new_mem_buf((void*)privateKeyStr, -1);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if(!rsaPrivKey)
    {
        mLastError.clear();
        mLastError.append("Could not load the private key ");
        mLastError.append(ERR_error_string(ERR_get_error(), NULL));
        qCritical() << mLastError;
    }
    BIO_free(bio);
    return rsaPrivKey;
}

RSA *TeCipher::getPrivateRSAKey(QString &filename)
{
    QByteArray byteArray = readFile(filename);
    return this->getPrivateRSAKey(byteArray);
}

QByteArray TeCipher::enryptRSA(RSA *key, QByteArray &data, bool isPublic)
{
    QByteArray finished;
    int dataSize = data.length();
    const unsigned char* dataToEcrypt = (const unsigned char*)data.constData();
    int rsaKeySize = RSA_size(key);

    unsigned char* encryptedData = (unsigned char*)malloc(rsaKeySize);
    int resultLen = -1;

    if(isPublic)
    {
        resultLen = RSA_public_encrypt(dataSize, dataToEcrypt, encryptedData, key, PADDING);
    }
    else
    {
        resultLen = RSA_private_encrypt(dataSize, dataToEcrypt, encryptedData, key, PADDING);
    }

    if(resultLen == -1)
    {
        mLastError.clear();
        mLastError += "Could not encrypt: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
        return finished;
    }
    QByteArray encryptedMessage = QByteArray(reinterpret_cast<char*>(encryptedData), resultLen);
    finished.append(encryptedMessage);
    free(encryptedData);
    return finished;
}

QByteArray TeCipher::decryptRSA(RSA *key, QByteArray &data, bool isPrivate)
{
    QByteArray finished;
    const unsigned char* encryptedData = (const unsigned char*)data.constData();
    int rsaKeyLen = RSA_size(key);
    unsigned char* decryptedData = (unsigned char*)malloc(rsaKeyLen);
    int resultLen = -1;

    if(isPrivate)
    {
        resultLen = RSA_private_decrypt(rsaKeyLen, encryptedData, decryptedData, key, PADDING);
    }
    else
    {
        resultLen = RSA_public_decrypt(rsaKeyLen, encryptedData, decryptedData, key, PADDING);
    }

    if(resultLen == -1)
    {
        mLastError.clear();
        mLastError += "Could not decrypt: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
        return finished;
    }

    QByteArray decryptedMessage = QByteArray::fromRawData((const char*)decryptedData, resultLen);
    finished.append(decryptedMessage);
    free(decryptedData);
    return finished;
}

QByteArray TeCipher::encryptAES(QByteArray &passphrase, QByteArray &data)
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
        mLastError.clear();
        mLastError += "EVP_BytesToKey() error: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
        return QByteArray();
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if(!EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(),
                          NULL, key, iv))
    {
        mLastError.clear();
        mLastError += "EVP_EncryptInit_ex failed: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
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
        mLastError.clear();
        mLastError += "EVP_EncryptInit_ex failed: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
        return QByteArray();
    }

    if(!EVP_EncryptUpdate(&ctx, cipher_text, &c_len, (unsigned char*)input, len))
    {
        mLastError.clear();
        mLastError += "EVP_EncodeUpdate failed: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
        return QByteArray();
    }

    if(!EVP_EncryptFinal(&ctx, cipher_text + c_len, &f_len))
    {
        mLastError.clear();
        mLastError += "EVP_EncryptFinal failed: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
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

QByteArray TeCipher::decryptAES(QByteArray &passphrase, QByteArray &data)
{
    QByteArray salz = data.mid(0, SALT_SIZE);
    if(QString(data.mid(0, SALT_SIZE)) == "Salted__")
    {
        salz = data.mid(SALT_SIZE, SALT_SIZE);
        data = data.mid(2 * SALT_SIZE);
    }
    else
    {
        mLastError = "Could not load salt from data!";
        qWarning() << mLastError;
        return QByteArray();
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
        mLastError.clear();
        mLastError += "EVP_BytesToKey() error: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
        return QByteArray();
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if(!EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        mLastError.clear();
        mLastError += "EVP_DecryptInit_ex failed: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
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
        mLastError.clear();
        mLastError += "EVP_DecryptUpdate: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
        return QByteArray();
    }

    if(!EVP_DecryptFinal(&ctx, plain_text + p_len, &f_len))
    {
        mLastError.clear();
        mLastError += "EVP_DecryptFinal: ";
        mLastError += ERR_error_string(ERR_get_error(), NULL);
        qCritical() << mLastError;
        return QByteArray();
    }

    len = p_len + f_len;
    EVP_CIPHER_CTX_cleanup(&ctx);

    QByteArray decryptedMessage = QByteArray(reinterpret_cast<char*>(plain_text), len);
    free(plain_text);
    return decryptedMessage;
}

bool TeCipher::encryptWithCombinedMethod(QByteArray &passphrase,
                                         QByteArray &toEncrypt,
                                         QByteArray &encrypted)
{
    if(mPublicKey.isEmpty())
    {
        mLastError = "RSA public key not loaded";
        qCritical() << mLastError;
        return false;
    }
    RSA* rsaPubKey = this->getPublicRSAKey(mPublicKey);
    QByteArray encryptedKey = this->enryptRSA(rsaPubKey, passphrase);
    this->freeRSAKey(rsaPubKey);
    QByteArray encryptedData = this->encryptAES(passphrase, toEncrypt);
    if(encryptedData.isEmpty())
    {
        qCritical() << mLastError;
        return false;
    }
    encrypted.append(encryptedKey);
    encrypted.append(encryptedData);
    return true;
}

bool TeCipher::decryptWithCombinedMethod(QByteArray &passphrase,
                                         QByteArray &toDecrypt,
                                         QByteArray &decrypted)
{
    if(mPrivateKey.isEmpty())
    {
        mLastError = "RSA private key not loaded";
        qCritical() << mLastError;
        return false;
    }

    QByteArray header("Salted__");
    int pos = toDecrypt.indexOf(header);

    if(pos == -1)
    {
        mLastError = "Could find the beginning of the encypted data";
        qCritical() << mLastError;
        return false;
    }

    QByteArray encryptedKey = toDecrypt.mid(0, 256);
    QByteArray encryptedData = toDecrypt.mid(256);

    RSA* privateKey = this->getPrivateRSAKey(mPrivateKey);
    QByteArray decryptedPassphrase = this->decryptRSA(privateKey, encryptedKey);
    this->freeRSAKey(privateKey);

    if(decryptedPassphrase != passphrase)
    {
        qDebug() << "decryptedPassphrase:";
        qDebug() << decryptedPassphrase;
        qDebug() << "Your passphrase:";
        qDebug() << passphrase;
        mLastError = "Wrong passphrase";
        qCritical() << mLastError;
        return false;
    }

    //qDebug() << "AES passphrase: " << passphrase;

    QByteArray plainText = this->decryptAES(decryptedPassphrase, encryptedData);
    if(plainText.isEmpty())
    {
        mLastError = "Could not decrypt file";
        qCritical() << mLastError;
        return false;
    }

    decrypted.clear();
    decrypted.append(plainText);
    return true;
}

QByteArray TeCipher::randomBytes(int size)
{
    unsigned char buf[size];
    RAND_bytes(buf, size);
    QByteArray array = QByteArray(reinterpret_cast<char*>(buf), size);
    return array;
}

void TeCipher::freeRSAKey(RSA *key)
{
    RSA_free(key);
}

QString TeCipher::getLastError() const
{
    return mLastError;
}

void TeCipher::initialize()
{
    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

void TeCipher::finalize()
{
    EVP_cleanup();
    ERR_free_strings();
}

QByteArray TeCipher::readFile(const QString &filename)
{
    QByteArray byteArray;
    QFile fi(filename);
    if(!fi.open(QFile::ReadOnly))
    {
        mLastError = fi.errorString();
        qCritical() << mLastError;
        return byteArray;
    }
    byteArray = fi.readAll();
    fi.close();
    return byteArray;
}

bool TeCipher::readFile(const QString &filename, QByteArray &data)
{
    QByteArray byteArray;
    QFile fi(filename);
    if(!fi.open(QFile::ReadOnly))
    {
        mLastError = fi.errorString();
        qCritical() << mLastError;
        return false;
    }
    data = fi.readAll();
    fi.close();
    return true;
}

bool TeCipher::writeFile(const QString &filename, QByteArray &data)
{
    QFile fo(filename);
    if(!fo.open(QFile::WriteOnly))
    {
        mLastError = fo.errorString();
        qCritical() << mLastError;
        return false;
    }
    fo.write(data);
    fo.close();
    return true;
}
