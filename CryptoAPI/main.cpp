#include "AES.h"
#include "GOST.h"
int main ()
{
    int operation,mode;
    string fpath,newfpath,ivfilepath,password;
    do {
        cout<<"Выберите операцию : 1 - AES , 2 - Gost , 0 - Exit = ";
        cin>>operation;
        if (operation == 1) {
            cout<<"Выберите режим работы алгоритма шифрования AES: 1 - Encode , 2 - Decode = ";
            cin>>mode;
            if (mode == 1) {
                try {
                    cout<<"Укажите путь до файла: "<<endl;
                    cin>>fpath;
                    cout<<"Укажите путь до файла, где будет сохранена зашифрованная информация: "<<endl;
                    cin>>newfpath;
                    cout << "Укажите пароль: ";
                    cin>>password;
                    algAES encoder(fpath,newfpath,password);
                    encoder.EncodeAES (encoder);
                    cout<<"Операция выполнена!"<<endl;
                } catch (CryptoPP::Exception &ex) {
                    cout<<ex.what()<<endl;
                }
            }
            if (mode == 2) {
                try {
                    cout << "Укажите путь до файла с зашифрованной информацией: ";
                    cin >> fpath;
                    cout << "Укажите путь до файла, где будет сохранена расшифрованная информация: ";
                    cin >> newfpath;
                    cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
                    cin >> ivfilepath;
                    cout << "Укажите пароль: ";
                    cin >> password;
                    algAES decoder (fpath,newfpath,password,ivfilepath);
                    decoder.DecodeAES (decoder);
                } catch (CryptoPP::Exception &ex) {
                    cout<<ex.what()<<endl;
                }
            }
        }
        if (operation == 2) {
            cout<<"Выберите режим работы алгоритма шифрования AES: 1 - Encode , 2 - Decode = ";
            cin>>mode;
            if (mode == 1) {
                try {
                    cout<<"Укажите путь до файла: "<<endl;
                    cin>>fpath;
                    cout<<"Укажите путь до файла, где будет сохранена зашифрованная информация: "<<endl;
                    cin>>newfpath;
                    cout << "Укажите пароль: ";
                    cin>>password;
                    algGOST encoder(fpath,newfpath,password);
                    encoder.EncodeGOST (encoder);
                    cout<<"Операция выполнена!"<<endl;
                } catch (CryptoPP::Exception &ex) {
                    cout<<ex.what()<<endl;
                }
            }
            if (mode == 2) {
                try {
                    cout << "Укажите путь до файла с зашифрованной информацией : ";
                    cin >> fpath;
                    cout << "Укажите путь до файла, где будет сохранена расшифрованная информация: ";
                    cin >> newfpath;
                    cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
                    cin >> ivfilepath;
                    cout << "Укажите пароль: ";
                    cin >> password;
                    algGOST decoder (fpath,newfpath,password,ivfilepath);
                    decoder.DecodeGOST (decoder);
                } catch (CryptoPP::Exception &ex) {
                    cout<<ex.what()<<endl;
                }
            }
        }
    } while (operation!=0);
}
