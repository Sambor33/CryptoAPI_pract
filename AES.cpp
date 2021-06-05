#include "AES.h"
algAES::algAES(const string& filepath, const string& newfilepath, const string& password)
{
    this->filepath = filepath;
    this->newfilepath = newfilepath;
    this->password = password;
}
algAES::algAES(const string& filepath, const string& newfilepath, const string& password, const string & iv)
{
    this->filepath = filepath;
    this->newfilepath = newfilepath;
    this->password = password;
    IVfilepath = iv;
}

void algAES::EncodeAES (algAES enc)
{
    //Ключ
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)enc.password.data(), enc.password.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);
    //IV
    AutoSeededRandomPool prng;
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    //Формируется файл с IV
    ofstream v_IV(string(enc.newfilepath + ".iv").c_str(), ios::out | ios::binary);
    v_IV.write((char*)iv, AES::BLOCKSIZE);
    v_IV.close();
    cout << "Файл с вектором инициализации: " << enc.newfilepath << ".iv" << endl;
    //Шифрование
    CBC_Mode<AES>::Encryption encr;
    encr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(enc.filepath.c_str(), true, new StreamTransformationFilter(encr, new FileSink(enc.newfilepath.c_str())));
    cout << "Зашифрованный файл: " << enc.newfilepath << endl;
}
void algAES::DecodeAES (algAES dec)
{
    //Ключ
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)dec.password.data(), password.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);
    //Запись IV из файла
    byte iv[AES::BLOCKSIZE];
    ifstream v_IV(dec.IVfilepath.c_str(), ios::in | ios::binary);
    //Проверка файла с IV
    if (v_IV.good()) {
        v_IV.read(reinterpret_cast<char*>(&iv), AES::BLOCKSIZE);
        v_IV.close();
    } else if (!v_IV.is_open()) {
        throw invalid_argument ("Ошибка: файл с IV не найден");
        v_IV.close();
    } 
    //Расшифрование
    CBC_Mode<AES>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(dec.filepath.c_str(), true, new StreamTransformationFilter(decr, new FileSink(dec.newfilepath.c_str())));
    cout << "Расшифрованный файл: " << dec.newfilepath << endl;
}
