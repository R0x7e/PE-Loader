#pragma once
#include <vector>
#include <string>
#include <windows.h>
#include <stdexcept>
#include <algorithm> // for std::min

//XorDecryptPE(fileBuffer, 0xAA);
void XorDecryptPE(std::vector<BYTE>& data, const std::vector<BYTE>& key);


//XorDecryptPE(fileBuffer, "s3cr3t_k3y!");
void XorDecryptPE(std::vector<BYTE>& data, const std::string& key);

void XorDecryptPE(std::vector<BYTE>& data, BYTE singleKey);

std::vector<BYTE> HexStringToKey(const std::string& hex);

// PE头校验,验证解密后的内容是否正确
bool IsValidPEHeader(const std::vector<BYTE>& data);


