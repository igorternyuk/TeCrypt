#include "tecypher.hpp"
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
    TeCypher cypher;
    RSA* pubKey = cypher.getPublicRSAKey(testPublicKey);
    RSA* privKey = cypher.getPrivateRSAKey(testPrivateKey);

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
    QByteArray encryptedMsg = cypher.enryptRSA(pubKey, msg);
    qDebug() << encryptedMsg.toBase64();
    QByteArray decryptedMsg = cypher.decryptRSA(privKey, encryptedMsg);
    qDebug() << "Decrypted message:";
    qDebug() << decryptedMsg;

    cypher.freeRSAKey(pubKey);
    cypher.freeRSAKey(privKey);

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
    TeCypher cypher;
    QByteArray pubKey = getPublicKey();
    RSA* rsaPubKey = cypher.getPublicRSAKey(pubKey);
    QByteArray passphrase = cypher.randomBytes(8); //Here must be user password
    QByteArray encryptedKey = cypher.enryptRSA(rsaPubKey, passphrase);
    qDebug() << "Encrypted RSA key => " << encryptedKey;
    QByteArray plainText = "The quick brown FOX jumps over the lazy dog!!!.";
    QByteArray encryptedData = cypher.encryptAES(passphrase, plainText);
    if(encryptedData.isEmpty())
    {
        qCritical() << "Could not encrypt";
        return false;
    }
    QByteArray out;
    out.append(encryptedKey);
    out.append(encryptedData);
    qDebug() << "Encrypted data" << encryptedData;
    cypher.freeRSAKey(rsaPubKey);
    return writeFile("fox.enc", out);
}

bool decryptCombined()
{
    TeCypher cypher;
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
    RSA* privateKey = cypher.getPrivateRSAKey(key);
    QByteArray passphrase = cypher.decryptRSA(privateKey, encryptedKey);
    cypher.freeRSAKey(privateKey);
    qDebug() << "AES passphrase: " << passphrase;


    QByteArray plainText = cypher.decryptAES(passphrase, encryptedData);
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

void testCombinedEncryption2()
{
    TeCypher cypher;
    cypher.loadPublicKeyByteArrayFromFile("public.pem");
    cypher.loadPrivateKeyByteArrayFromFile("private.pem");
    QByteArray password = "!!!@@@###$$$^^^&&&&5555mp3";
    QByteArray textToEcrypt = "The quick brown FOX jumps over the lazy dog!!!!!!!!";
    qDebug() << "Text to encrypt: ";
    qDebug() << textToEcrypt;
    QByteArray encryptedBytes;
    cypher.encryptWithCombinedMethod(password, textToEcrypt, encryptedBytes);
    qDebug() << "Encrypted bytes: ";
    qDebug() << encryptedBytes;
    QByteArray decryptedBytes;
    cypher.decryptWithCombinedMethod(password, encryptedBytes, decryptedBytes);
    qDebug() << "Decrypted bytes: ";
    qDebug() << decryptedBytes;
}

void testAES()
{
    qDebug() << "Testing AES...";
    QByteArray passphrase = "contrasenya";
    TeCypher cypher;
    qDebug() << "Message to encrypte:";
    QByteArray msg = "The quick brown fox jumps over the lazy dog.";
    qDebug() << msg;
    QByteArray encryptedMsg = cypher.encryptAES(passphrase, msg);
    qDebug() << "Encrypted message:";
    qDebug() << encryptedMsg;
    QByteArray decryptedMsg = cypher.decryptAES(passphrase, encryptedMsg);
    qDebug() << "Decrypted message:";
    qDebug() << decryptedMsg;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    //testRSA();
    //testAES();
    testCombinedEncryption2();
    signal(SIGINT, cleanup);
    return app.exec();
}
