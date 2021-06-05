#pragma once
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include "cryptopp/modes.h"
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
using namespace CryptoPP;

class algAES
{
private:
  string filepath;
  string newfilepath;
  string password;
  string IVfilepath;
  string salt = "Соль земли русской";
public:
  algAES(const string& filepath, const string& newfilepath, const string& Pass);
  algAES(const string& filepath, const string& newfilepath, const string& Pass, const string & iv);
  void EncodeAES (algAES enc);
  void DecodeAES (algAES dec);
};
