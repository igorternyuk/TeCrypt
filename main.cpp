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
    RSA* pubKey = cypher.getPublicKey(testPublicKey);
    RSA* privKey = cypher.getPrivateKey(testPrivateKey);

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

void readFile(const QString &filename, QByteArray &data)
{
    QFile file(filename);
    if(!file.open(QFile::ReadOnly))
    {
        qCritical() << "Could not open file " << filename;
        return;
    }
    data = file.readAll();
    file.close();
}

void writeFile(const QString &filename, QByteArray &data)
{
    QFile file(filename);
    if(!file.open(QFile::WriteOnly))
    {
        qCritical() << "Could not open file " << filename;
        return;
    }
    file.write(data);
    file.close();
}

bool encryptCombined()
{
    TeCypher cypher;
    QByteArray pubKey = getPublicKey();
    RSA* rsaPubKey = cypher.getPublicKey(pubKey);
}

bool decryptCombined()
{

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
    testRSA();
    testAES();
    signal(SIGINT, cleanup);
    return app.exec();
}
