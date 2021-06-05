#pragma once
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/gost.h>
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
class algGOST
{
private:
  string filepath;
  string newfilepath;
  string password;
  string IVfilepath;
  string salt = "Соль земли русской";
public:
  algGOST(const string& filepath, const string& newfilepath, const string& Pass);
  algGOST(const string& filepath, const string& newfilepath, const string& Pass, const string & iv);
  void EncodeGOST (algGOST enc);
  void DecodeGOST (algGOST dec);
};