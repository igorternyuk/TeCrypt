#include "tecypher.hpp"

#include <QDebug>

TeCypher::TeCypher(QObject *parent):
    QObject(parent)
{

}

RSA *TeCypher::getPublicKey(QByteArray &data)
{

}

RSA *TeCypher::getPublicKey(QFile &filename)
{

}

RSA *TeCypher::getPrivateKey(QByteArray &data)
{

}

RSA *TeCypher::getPrivateKey(QFile &filename)
{

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

}

void TeCypher::finalize()
{

}

QByteArray TeCypher::readFile(const QString &filename)
{

}

void TeCypher::writeFile(const QString &filename, QByteArray &data)
{

}
