#include "GOST.h"
algGOST::algGOST(const string& filepath, const string& newfilepath, const string& password)
{
    this->filepath = filepath;
    this->newfilepath = newfilepath;
    this->password = password;
}
algGOST::algGOST(const string& filepath, const string& newfilepath, const string& password, const string & iv)
{
    this->filepath = filepath;
    this->newfilepath = newfilepath;
    this->password = password;
    IVfilepath = iv;
}

void algGOST::EncodeGOST (algGOST enc)
{
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)enc.password.data(), enc.password.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);
    AutoSeededRandomPool prng;
    byte iv[GOST::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    ofstream v_IV(string(enc.newfilepath + ".iv").c_str(), ios::out | ios::binary);
    v_IV.write((char*)iv, GOST::BLOCKSIZE);
    v_IV.close();
    cout << "Файл с вектором инициализации: " << enc.newfilepath << ".iv" << endl;
    CBC_Mode<GOST>::Encryption encr;
    encr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(enc.filepath.c_str(), true, new StreamTransformationFilter(encr, new FileSink(enc.newfilepath.c_str())));
    cout << "Зашифрованный файл: " << enc.newfilepath << endl;
}

void algGOST::DecodeGOST (algGOST dec)
{
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)dec.password.data(), password.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);
    byte iv[GOST::BLOCKSIZE];
    ifstream v_IV(dec.IVfilepath.c_str(), ios::in | ios::binary);
    if (v_IV.good()) {
        v_IV.read(reinterpret_cast<char*>(&iv), GOST::BLOCKSIZE);
        v_IV.close();
    } else if (!v_IV.is_open()) {
        throw invalid_argument ("Ошибка: файл с IV не найден");
        v_IV.close();
    } 
    CBC_Mode<GOST>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(dec.filepath.c_str(), true, new StreamTransformationFilter(decr, new FileSink(dec.newfilepath.c_str())));
    cout << "Расшифрованный файл : " << dec.newfilepath << endl;
}