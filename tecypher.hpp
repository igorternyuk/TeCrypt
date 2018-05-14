#pragma once

#include <QObject>
#include <QFile>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PADDING RSA_PKCS1_PADDING
#define KEY_SIZE 32
#define IV_SIZE 32
#define BLOCK_SIZE 256
#define SALT_SIZE 8
#define ROUNDS 1

class TeCypher: public QObject
{
    Q_OBJECT

public:
    explicit TeCypher(QObject *parent = nullptr);
    ~TeCypher();

    /**
     * @brief Loads the public key from a byte array
     * @param data The byte array
     * @return RSA
     */
    RSA* getPublicKey(QByteArray &data);

    /**
     * @brief Loads the public key from a file
     * @param filename file to load
     * @return RSA
     */
    RSA *getPublicKey(QString &filename);

    /**
     * @brief Loads the private key from a byte array
     * @param data The byte array
     * @return RSA
     */
    RSA* getPrivateKey(QByteArray &data);

    /**
     * @brief Loads the private key from a file
     * @param filename The file to load
     * @return RSA
     */
    RSA* getPrivateKey(QString &filename);

    /**
     * @brief enryptRSA
     * @param key either RSA public key or RSA private key
     * @param data The data to enrypt
     * @param isPublic equals true if the key is RSA public key
     *  and false in the contrary case
     * @return encrypted data
     */
    QByteArray enryptRSA(RSA* key, QByteArray &data, bool isPublic = true);

    /**
     * @brief decryptRSA
     * @param key either RSA private key or RSA public key
     * @param data The data to decrypt
     * @param isPrivate equals true if the key is RSA private key
     *  and false in the contrary case
     * @return  decrypted data
     */
    QByteArray decryptRSA(RSA* key, QByteArray &data, bool isPrivate = true);

    /**
     * @brief encrypts a byte array with AES 256 CBC
     * @param passphrase The passphrase byte array
     * @param data The data to encrypt
     * @return
     */

    QByteArray encryptAES(QByteArray &passphrase, QByteArray &data);

    /**
     * @brief decrypts a byte array with AES 256 CBC
     * @param passphrase The passphrase byte array
     * @param data The data to decrypt
     * @return
     */
    QByteArray decryptAES(QByteArray &passphrase, QByteArray &data);

    QByteArray randomBytes(int size);

    void freeRSAKey(RSA* key);

private:
    /**
     * @brief Initializes OpenSSL library
     */
    void initialize();

    /**
     * @brief Finalizes OpenSSL library
     */
    void finalize();

    /**
     * @brief readFile Loads a file and returns a byte array
     * @param filename A name of a file to read from
     * @return
     */
    QByteArray readFile(const QString& filename);

    /**
     * @brief writeFile Writes a bytearray to a file
     * @param filename A name of a file to write to
     * @param data The byte array to write
     */
    void writeFile(const QString& filename, QByteArray &data);
};
