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
    RSA_free(pubKey);
    RSA_free(privKey);
    qDebug() << "The memory was freed...";
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    testRSA();
    signal(SIGINT, cleanup);
    return app.exec();
}
