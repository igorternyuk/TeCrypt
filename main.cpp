#include "tecipher.hpp"
#include <QCoreApplication>
#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <signal.h>

static void cleanup(int sig)
{
    qDebug() << "Application is shutting down...";
    if (sig == SIGINT)
    {
        qApp->quit();
    }
}

/*
Generate a private key for RSA:
openssl genrsa -out private.pem 2048
Generate the public key for private key:
openssl rsa -in private.pem -pubout > public.pem
*/

QByteArray getPrivateKey()
{
    QByteArray byteArray;
    QFile fi("private.pem");
    if(fi.open(QIODevice::ReadOnly | QIODevice::Text))
    {
       qDebug() << "File private.pem opened";
       byteArray = fi.readAll();
       fi.close();
    }
    else
    {

        qCritical() << "Could not open the file with private key: "
                    << fi.errorString();
    }
    return byteArray;
}

QByteArray getPublicKey()
{
    QByteArray byteArray;
    QFile fi("public.pem");
    if(fi.open(QIODevice::ReadOnly | QIODevice::Text))
    {
       qDebug() << "File public.pem opened";
       byteArray = fi.readAll();
       fi.close();
    }
    else
    {
        qCritical() << "Could not open the file with public key"
                    << fi.errorString();
    }
    return byteArray;
}

void testRSA()
{
    qDebug() << "Testing RSA...";
    qDebug() << "Loading keys...";
    QByteArray testPublicKey = getPublicKey();
    QByteArray testPrivateKey = getPrivateKey();
    TeCipher cipher;
    RSA* pubKey = cipher.getPublicRSAKey(testPublicKey);
    RSA* privKey = cipher.getPrivateRSAKey(testPrivateKey);

    if(pubKey && privKey)
    {
        qDebug() << "The keys were successfully loaded...";
    }
    else
    {
        qDebug() << "Some errors occured...";
    }
    qDebug() << "Message to encrypte:";
    QByteArray msg = "The quick brown fox jumps over the lazy dog!!!";
    qDebug() << msg;
    qDebug() << "Encrypted message:";
    QByteArray encryptedMsg = cipher.enryptRSA(pubKey, msg);
    qDebug() << encryptedMsg.toBase64();
    QByteArray decryptedMsg = cipher.decryptRSA(privKey, encryptedMsg);
    qDebug() << "Decrypted message:";
    qDebug() << decryptedMsg;

    cipher.freeRSAKey(pubKey);
    cipher.freeRSAKey(privKey);

    qDebug() << "The memory was freed...";
}

bool readFile(const QString &filename, QByteArray &data)
{
    QFile file(filename);
    if(!file.open(QFile::ReadOnly))
    {
        qCritical() << "Could not open file " << filename;
        return false;
    }
    data = file.readAll();
    file.close();
    return true;
}

bool writeFile(const QString &filename, QByteArray &data)
{
    QFile file(filename);

    if(!file.open(QFile::WriteOnly))
    {
        qCritical() << "Could not open file " << filename;
        return false;
    }

    file.write(data);
    file.close();
    return true;
}

bool encryptCombined()
{
    TeCipher cipher;
    QByteArray pubKey = getPublicKey();
    RSA* rsaPubKey = cipher.getPublicRSAKey(pubKey);
    QByteArray passphrase = cipher.randomBytes(8); //Here must be user password
    QByteArray encryptedKey = cipher.enryptRSA(rsaPubKey, passphrase);
    qDebug() << "Encrypted RSA key => " << encryptedKey;
    QByteArray plainText = "The quick brown FOX jumps over the lazy dog!!!.";
    QByteArray encryptedData = cipher.encryptAES(passphrase, plainText);
    if(encryptedData.isEmpty())
    {
        qCritical() << "Could not encrypt";
        return false;
    }
    QByteArray out;
    out.append(encryptedKey);
    out.append(encryptedData);
    qDebug() << "Encrypted data" << encryptedData;
    cipher.freeRSAKey(rsaPubKey);
    return writeFile("fox.enc", out);
}

bool decryptCombined()
{
    TeCipher cipher;
    QByteArray data;

    QString filename = "fox.enc";
    if(!readFile(filename, data))
    {
        qCritical() << "Could not open file: " << filename;
        return false;
    }

    QByteArray header("Salted__");
    int pos = data.indexOf(header);

    if(pos == -1)
    {
        qCritical() << "Could find the beginning of the encypted file";
        return false;
    }

    QByteArray encryptedKey = data.mid(0, 256);
    QByteArray encryptedData = data.mid(256);

    QByteArray key = getPrivateKey(); //The problem
    RSA* privateKey = cipher.getPrivateRSAKey(key);
    QByteArray passphrase = cipher.decryptRSA(privateKey, encryptedKey);
    cipher.freeRSAKey(privateKey);
    qDebug() << "AES passphrase: " << passphrase;


    QByteArray plainText = cipher.decryptAES(passphrase, encryptedData);
    if(plainText.isEmpty())
    {
        qCritical() << "Could not decrypt file";
        return false;
    }

    return writeFile("fox.txt", plainText);
}

void testCombinedEncryption()
{
    qDebug() << "Combined encryption test...";
    if(encryptCombined())
    {
        decryptCombined();
    }
}


void testAES()
{
    qDebug() << "Testing AES...";
    QByteArray passphrase = "contrasenya";
    TeCipher cipher;
    qDebug() << "Message to encrypte:";
    QByteArray msg = "The quick brown fox jumps over the lazy dog.";
    qDebug() << msg;
    QByteArray encryptedMsg = cipher.encryptAES(passphrase, msg);
    qDebug() << "Encrypted message:";
    qDebug() << encryptedMsg;
    QByteArray decryptedMsg = cipher.decryptAES(passphrase, encryptedMsg);
    qDebug() << "Decrypted message:";
    qDebug() << decryptedMsg;
}

void testCombinedEncryption2()
{
    TeCipher cipher;
    cipher.loadPublicKeyByteArrayFromFile("public.pem");
    cipher.loadPrivateKeyByteArrayFromFile("private.pem");
    QByteArray password = "!!!@@@###$$$^^^&&&&5555mp3";
    QByteArray textToEcrypt = "The quick brown FOX jumps over the lazy dog!!!!!!!!";
    qDebug() << "Text to encrypt: ";
    qDebug() << textToEcrypt;
    QByteArray encryptedBytes;
    cipher.encryptWithCombinedMethod(password, textToEcrypt, encryptedBytes);
    qDebug() << "Encrypted bytes: ";
    qDebug() << encryptedBytes;
    QByteArray decryptedBytes;
    cipher.decryptWithCombinedMethod(password, encryptedBytes, decryptedBytes);
    qDebug() << "Decrypted bytes: ";
    qDebug() << decryptedBytes;
}

void testPlainTextEncryption()
{
    qDebug() << "Plain text encryption test...";
    TeCipher cipher;
    cipher.loadPublicKeyByteArrayFromFile("public.pem");
    cipher.loadPrivateKeyByteArrayFromFile("private.pem");
    QString password = "ParolNaGorshkeSidelKorol";
    QString textToEncrypt = "«Ля́пис Трубецко́й» — белорусская панк-рок-группа, названная"
                            " в честь комического героя романа Ильи Ильфа и"
                            " Евгения Петрова «Двенадцать стульев»,"
                            " поэта-халтурщика Никифора Ляписа, "
                            " который печатался под псевдонимом Трубецкой."
                            " 17 марта 2014 года Сергей Михалок объявил о роспуске группы,"
                            " и 31 августа группа прекратила свою деятельность";
    qDebug() << "Text to encrypt: ";
    qDebug() << textToEncrypt;
    QString encryptedText;
    if(!cipher.encryptPlainTextWithCombinedMethod(password, textToEncrypt,
                                                  encryptedText))
    {
        qCritical() << "Encryption failed: " << cipher.getLastError();
        return;
    }
    qDebug() << "Encrypted text: ";
    qDebug() << encryptedText;

    QString decryptedText;
    if(!cipher.decryptPlainTextWithCombinedMethod(password, encryptedText,
                                                  decryptedText))
    {
        qCritical() << "Decryption failed: " << cipher.getLastError();
        return;
    }
    qDebug() << "Decrypted text: ";
    qDebug() << decryptedText;
}

void testFileEncryption()
{
    qDebug() << "File encryption test...";
    TeCipher cipher;
    cipher.loadPublicKeyByteArrayFromFile("public.pem");
    cipher.loadPrivateKeyByteArrayFromFile("private.pem");
    QString password = "ParolNaGorshkeSidelKorol";
    cipher.encryptFileWithCombinedMethod(password, "lapiz.txt", "lapiz.enc");
    cipher.decryptFileWithCombinedMethod(password, "lapiz.enc", "lapiz.dec");
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    //testRSA();
    //testAES();
    //testCombinedEncryption2();
    testPlainTextEncryption();
    //testFileEncryption();
    signal(SIGINT, cleanup);
    return app.exec();
}
