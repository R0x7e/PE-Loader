#pragma once
#include <vector>
#include <windows.h>
#include <cstdlib> // for strtol
#include <string>
std::vector<BYTE> DownloadPEFromUrl(const char* url);