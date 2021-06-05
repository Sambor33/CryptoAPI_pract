#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
int main ()
{
    CryptoPP::SHA1 hash;
    cout <<"Название алгоритма хэширования: " << hash.AlgorithmName() << endl; 
    cout << "Размер хэша: " << hash.DigestSize() << endl;
    cout << "Размер внутреннего блока: " << hash.BlockSize() << endl; 
    string path = "Test.txt"; 
    string Message, content;
    fstream file;
    file.open(path);
    if(!file.is_open()) {
        cout << "Ошибка: невозможо открыть файл" << endl;
        return 1;
    }
    while(true) {
        getline(file,Message);
        if (file.fail()) 
            break;
        content += Message;
    }
    cout << "Содержимое файла: " << content << endl; 
    vector<byte> digest (hash.DigestSize());
    hash.Update(reinterpret_cast<const byte*>(content.data()),content.size()); // формируем хэш
    hash.Final(digest.data()); 
    cout << "Хэш в шестнадцатиричном формате: ";
    CryptoPP::StringSource(digest.data(),digest.size(),true, new  CryptoPP::HexEncoder(new  CryptoPP::FileSink(cout))); 
    cout << endl;
    return 0;
}
