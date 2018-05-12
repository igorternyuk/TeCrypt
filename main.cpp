#include <QCoreApplication>
#include <QFile>
#include <QTextStream>
#include <QDebug>

QByteArray getPrivateKey()
{
    QByteArray byteArray;
    QFile fi("private.pem");
    if(fi.open(QIODevice::ReadOnly | QIODevice::Text))
    {
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

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    return app.exec();
}
