#include "XorDecryptPE.h"

// 核心解密函数
// 原地解密（修改原缓冲区），支持任意二进制密钥
void XorDecryptPE(std::vector<BYTE>& data, const std::vector<BYTE>& key) {
    if (data.empty() || key.empty())
        throw std::invalid_argument("Data or key is empty");

    const size_t keySize = key.size();
    BYTE* ptr = data.data();
    const size_t size = data.size();

    for (size_t i = 0; i < size; ++i) {
        ptr[i] ^= key[i % keySize];
    }
}

// 重载：支持std::string密钥
void XorDecryptPE(std::vector<BYTE>& data, const std::string& key) {
    if (key.empty())
        throw std::invalid_argument("Key string is empty");
    XorDecryptPE(data, std::vector<BYTE>(key.begin(), key.end()));
}

// 重载：单字节密钥
void XorDecryptPE(std::vector<BYTE>& data, BYTE singleKey) {
    BYTE key = singleKey;
    std::for_each(data.begin(), data.end(), [key](BYTE& b) { b ^= key; });
}

// 辅助工具函数
// 十六进制字符串转字节数组（例："5A3F" -> {0x5A, 0x3F}）
std::vector<BYTE> HexStringToKey(const std::string& hex) {
    if (hex.empty() || hex.size() % 2 != 0)
        throw std::invalid_argument("Invalid hex string length");

    std::vector<BYTE> key;
    key.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte;
        if (sscanf_s(hex.c_str() + i, "%2x", &byte) != 1) // Windows安全版
            throw std::runtime_error("Invalid hex character");
        key.push_back(static_cast<BYTE>(byte));
    }
    return key;
}

// PE头校验,验证解密后的内容是否正确
bool IsValidPEHeader(const std::vector<BYTE>& data) {
    if (data.size() < 2) return false;
    // 检查DOS头 "MZ"
    return (data[0] == 'M' && data[1] == 'Z');
}

// ==================== 使用示例 ====================
/*
// 场景1：单字节密钥（最常见）
XorDecryptPE(fileBuffer, 0xAA);

// 场景2：字符串密钥（含特殊字符）
XorDecryptPE(fileBuffer, "s3cr3t_k3y!");

// 场景3：十六进制密钥字符串（从配置读取）
auto key = HexStringToKey("DEADBEEF"); // 转为4字节密钥
XorDecryptPE(fileBuffer, key);

// 场景4：解密后验证PE有效性
if (!IsValidPEHeader(fileBuffer)) {
    // 处理解密失败：密钥错误/文件损坏
    throw std::runtime_error("Invalid PE after decryption");
}
// 后续可安全进行PE加载操作
*/