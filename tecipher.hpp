#pragma once

#include <QObject>

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

class TeCipher: public QObject
{
    Q_OBJECT

public:
    explicit TeCipher(QObject *parent = nullptr);
    ~TeCipher();

    /**
     * @brief loadPublicKeyByteArrayFromFile
     * @param pathToPublicKeyFile path to the file with RSA public key
     * @return true in the case of success and false if the loading fails
     */
    bool loadPublicKeyByteArrayFromFile(const QString &pathToPublicKeyFile);

    /**
     * @brief loadPrivateKeyByteArrayFromFile
     * @param pathToPrivateKeyFile path to the file with RSA private key
     * @return true in the case of success and false if the loading fails
     */
    bool loadPrivateKeyByteArrayFromFile(const QString &pathToPrivateKeyFile);

    /**
     * @brief loads the public key from a byte array
     * @param data The byte array
     * @return RSA
     */
    RSA* getPublicRSAKey(QByteArray &data);

    /**
     * @brief loads the public key from a file
     * @param filename file to load
     * @return RSA
     */
    RSA *getPublicRSAKey(QString &filename);

    /**
     * @brief loads the private key from a byte array
     * @param data The byte array
     * @return RSA
     */
    RSA* getPrivateRSAKey(QByteArray &data);

    /**
     * @brief loads the private key from a file
     * @param filename The file to load
     * @return RSA
     */
    RSA* getPrivateRSAKey(QString &filename);

    /**
     * @brief enryptRSA
     * @param key either RSA public key or RSA private key
     * @param data data to enrypt
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
     * @param passphrase passphrase byte array
     * @param data data to encrypt
     * @return
     */

    QByteArray encryptAES(QByteArray &passphrase, QByteArray &data);

    /**
     * @brief decryptAES decrypts a byte array encrypted with AES 256 CBC
     * @param passphrase passphrase byte array
     * @param data data to decrypt
     * @return
     */
    QByteArray decryptAES(QByteArray &passphrase, QByteArray &data);

    /**
     * @brief encryptWithCombinedMethod
     * @param passphrase AES passphrase
     * @param textToEncrypt the array of bytes to be encrypted
     * @param encryptedText encrypted text
     * @return true if the encryption finished with success and false if it fails
     */
    bool encryptWithCombinedMethod(QByteArray &passphrase,
                                   QByteArray &toEncrypt,
                                   QByteArray &encrypted);

    /**
     * @brief decryptTextWithCombinedMethod
     * @param passphrase AES passphrase
     * @param textToDecrypt array of bytes to be decrypted
     * @param decryptedText decrypted text
     * @return true if the decryption finished with success and false if it fails
     */
    bool decryptWithCombinedMethod(QByteArray &passphrase,
                                   QByteArray &toDecrypt,
                                   QByteArray &decrypted);

    /**
     * @brief encryptPlainTextWithCombinedMethod
     * @param password aes password
     * @param textToEcrypt text to be encrypted
     * @param encryptedText encrypted text
     * @return true if the encryption finished with success and false if it fails
     */
    bool encryptPlainTextWithCombinedMethod(const QString &password,
                                            QString &textToEcrypt,
                                            QString &encryptedText);

    /**
     * @brief decryptPlainTextWithCombinedMethod
     * @param password aes password
     * @param textToDecrypt text to be decrypted
     * @param decryptedText decrypted text
     * @return true if the decryption finished with success and false if it fails
     */
    bool decryptPlainTextWithCombinedMethod(const QString &password,
                                            QString &textToDecrypt,
                                            QString &decryptedText);

    /**
     * @brief encryptFileWithCombinedMethod
     * @param password aes password
     * @param pathToInputFile path to the file to be encrypted
     * @param pathToOutputFile path to the target encrypted file
     * @return true if the encryption finished with success and false if it fails
     */
    bool encryptFileWithCombinedMethod(const QString &password,
                                       const QString &pathToInputFile,
                                       const QString &pathToOutputFile);

    /**
     * @brief decryptFileWithCombinedMethod
     * @param password aes password
     * @param pathToInputFile path to the file to be decrypted
     * @param pathToOutputFile path to the target decrypted file
     * @return true if the decryption finished with success and false if it fails
     */
    bool decryptFileWithCombinedMethod(const QString &password,
                                       const QString &pathToInputFile,
                                       const QString &pathToOutputFile);

    /**
     * @brief randomBytes generates array of random bytes with specified length
     * @param size length of the generated array of bytes
     * @return
     */
    QByteArray randomBytes(int size);

    /**
     * @brief freeRSAKey deallocates specified RSA key memory
     * @param key
     */
    void freeRSAKey(RSA* key);

    /**
     * @brief readFile loads a file and returns a byte array
     * @param filename a name of a file to read from
     * @return
     */
    QByteArray readFile(const QString& filename);

    /**
     * @brief readFile loads a files content to the array of bytes
     * @param filename a name of a file to read from
     * @param data array of bytes to load to
     */
    bool readFile(const QString &filename, QByteArray &data);

    /**
     * @brief writeFile Writes a bytearray to a file
     * @param filename A name of a file to write to
     * @param data The byte array to write
     */
    bool writeFile(const QString& filename, QByteArray &data);

    /**
     * @brief getLastError
     * @return last occured error
     */
    QString getLastError() const;

private:
    QByteArray mPublicKey;
    QByteArray mPrivateKey;
    QString mLastError;

    /**
     * @brief Initializes OpenSSL library
     */
    void initialize();

    /**
     * @brief Finalizes OpenSSL library
     */
    void finalize();
};
