package com.example.cloudhsm;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MigrateProtectKeyStep2 {

    public static void main(String[] args) {
        try {
            String privateKeyPath = "../openssl-key/ec_private_key.pem";
            String publicKeyPath = "../openssl-key/migration-key-public.pem";
            String pkcs8KeyPath = "../openssl-key/ec_private_key_pkcs8.der";
            String encryptedKeyPath = "../openssl-key/ec_private_key.pem-encrypted";

            if (!Files.exists(Paths.get(privateKeyPath))) {
                System.err.println("错误：未找到私钥文件: " + privateKeyPath);
                System.exit(1);
            }

            if (!Files.exists(Paths.get(publicKeyPath))) {
                System.err.println("错误：未找到公钥文件: " + publicKeyPath);
                System.exit(1);
            }

            System.out.println("步骤1: 转换 EC 私钥为 PKCS8 DER 格式...");
            
            // 先转换为 PKCS8 DER 格式
            ProcessBuilder pb1 = new ProcessBuilder(
                "openssl", "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in", privateKeyPath,
                "-outform", "DER",
                "-out", pkcs8KeyPath
            );
            pb1.redirectErrorStream(true);
            Process process1 = pb1.start();
            
            BufferedReader reader1 = new BufferedReader(new InputStreamReader(process1.getInputStream()));
            String line;
            while ((line = reader1.readLine()) != null) {
                System.out.println(line);
            }
            
            int exitCode1 = process1.waitFor();
            if (exitCode1 != 0) {
                System.err.println("PKCS8 转换失败，退出码: " + exitCode1);
                System.exit(1);
            }
            
            System.out.println("PKCS8 DER 文件: " + pkcs8KeyPath);
            System.out.println("文件大小: " + Files.size(Paths.get(pkcs8KeyPath)) + " 字节");

            System.out.println("\n步骤2: 使用 RSA-OAEP-SHA512 加密 PKCS8 密钥...");
            System.out.println("公钥文件: " + publicKeyPath);

            // 使用 RSA-OAEP-SHA512 加密
            ProcessBuilder pb2 = new ProcessBuilder(
                "openssl", "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey", publicKeyPath,
                "-in", pkcs8KeyPath,
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha512",
                "-pkeyopt", "rsa_mgf1_md:sha512",
                "-out", encryptedKeyPath
            );

            pb2.redirectErrorStream(true);
            Process process2 = pb2.start();

            BufferedReader reader2 = new BufferedReader(new InputStreamReader(process2.getInputStream()));
            while ((line = reader2.readLine()) != null) {
                System.out.println(line);
            }

            int exitCode2 = process2.waitFor();
            if (exitCode2 != 0) {
                System.err.println("OpenSSL 加密失败，退出码: " + exitCode2);
                System.exit(1);
            }

            long fileSize = Files.size(Paths.get(encryptedKeyPath));
            System.out.println("\n加密成功！");
            System.out.println("加密文件: " + encryptedKeyPath);
            System.out.println("文件大小: " + fileSize + " 字节");

        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
