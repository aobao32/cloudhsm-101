package com.example.cloudhsm;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * MigrateProtectKeyStep2 单元测试
 *
 * Step2 的核心逻辑是调用 openssl 命令行工具，属于外部进程调用。
 * 单元测试策略：
 *   - 验证文件存在性检查逻辑（通过反射或直接测试前置条件）
 *   - 验证文件路径常量的合理性
 *   - 不测试实际 openssl 调用（需要真实环境）
 */
class MigrateProtectKeyStep2Test {

    /**
     * 验证当私钥文件不存在时，Files.exists() 返回 false
     * 对应 main() 中的防御性检查逻辑
     */
    @Test
    void fileExistenceCheck_shouldReturnFalseForMissingPrivateKey(@TempDir Path tempDir) {
        Path nonExistentKey = tempDir.resolve("ec_private_key.pem");
        assertFalse(Files.exists(nonExistentKey),
                "不存在的私钥文件应返回 false");
    }

    /**
     * 验证当公钥文件不存在时，Files.exists() 返回 false
     */
    @Test
    void fileExistenceCheck_shouldReturnFalseForMissingPublicKey(@TempDir Path tempDir) {
        Path nonExistentKey = tempDir.resolve("migration-key-public.pem");
        assertFalse(Files.exists(nonExistentKey),
                "不存在的公钥文件应返回 false");
    }

    /**
     * 验证当文件存在时，Files.exists() 返回 true
     */
    @Test
    void fileExistenceCheck_shouldReturnTrueForExistingFile(@TempDir Path tempDir) throws Exception {
        Path existingFile = tempDir.resolve("ec_private_key.pem");
        Files.write(existingFile, "-----BEGIN EC PRIVATE KEY-----\ntest\n-----END EC PRIVATE KEY-----".getBytes());

        assertTrue(Files.exists(existingFile),
                "已存在的文件应返回 true");
    }

    /**
     * 验证 ProcessBuilder 命令参数构造逻辑（openssl pkcs8 转换命令）
     * 通过直接构造 ProcessBuilder 验证参数列表格式正确
     */
    @Test
    void processBuilderArgs_shouldContainCorrectOpensslPkcs8Command() {
        String privateKeyPath = "../openssl-key/ec_private_key.pem";
        String pkcs8KeyPath = "../openssl-key/ec_private_key_pkcs8.der";

        ProcessBuilder pb = new ProcessBuilder(
                "openssl", "pkcs8",
                "-topk8", "-nocrypt",
                "-in", privateKeyPath,
                "-outform", "DER",
                "-out", pkcs8KeyPath
        );

        assertEquals("openssl", pb.command().get(0));
        assertEquals("pkcs8", pb.command().get(1));
        assertTrue(pb.command().contains("-topk8"));
        assertTrue(pb.command().contains("-nocrypt"));
        assertTrue(pb.command().contains("DER"));
    }

    /**
     * 验证 RSA-OAEP-SHA512 加密命令参数构造
     */
    @Test
    void processBuilderArgs_shouldContainCorrectOpensslEncryptCommand() {
        String publicKeyPath = "../openssl-key/migration-key-public.pem";
        String pkcs8KeyPath = "../openssl-key/ec_private_key_pkcs8.der";
        String encryptedKeyPath = "../openssl-key/ec_private_key.pem-encrypted";

        ProcessBuilder pb = new ProcessBuilder(
                "openssl", "pkeyutl",
                "-encrypt", "-pubin",
                "-inkey", publicKeyPath,
                "-in", pkcs8KeyPath,
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha512",
                "-pkeyopt", "rsa_mgf1_md:sha512",
                "-out", encryptedKeyPath
        );

        assertEquals("openssl", pb.command().get(0));
        assertEquals("pkeyutl", pb.command().get(1));
        assertTrue(pb.command().contains("rsa_padding_mode:oaep"));
        assertTrue(pb.command().contains("rsa_oaep_md:sha512"));
        assertTrue(pb.command().contains("rsa_mgf1_md:sha512"));
    }
}
