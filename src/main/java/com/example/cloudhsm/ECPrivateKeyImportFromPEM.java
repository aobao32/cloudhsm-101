package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyType;
import com.amazonaws.cloudhsm.jce.provider.attributes.EcParams;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

/**
 * 从PEM文件导入EC私钥到CloudHSM
 * 支持设置自定义标签和永久密钥属性
 */
public class ECPrivateKeyImportFromPEM {
    
    public static void main(String[] args) {
        try {
            Security.addProvider(new CloudHsmProvider());
            
            String hsmUser = System.getenv("HSM_USER");
            String hsmPassword = System.getenv("HSM_PASSWORD");
            
            if (hsmUser == null || hsmPassword == null) {
                System.err.println("错误：请设置环境变量 HSM_USER 和 HSM_PASSWORD");
                System.exit(1);
            }
            
            System.out.println("=== CloudHSM EC私钥导入演示（从PEM文件）===");
            System.out.println("使用用户: " + hsmUser + " 连接到CloudHSM...");
            
            String keyLabel = "myImportedPrivateKeyFromPEM";
            System.out.println("密钥标签: " + keyLabel);
            
            PrivateKey importedKey = importECPrivateKeyFromPEM(keyLabel);
            validateImportedKey(importedKey);
            
            System.out.println("\n✅ EC私钥永久导入成功完成！");
            System.out.println("密钥已作为永久密钥存储在CloudHSM中，标签为: " + keyLabel);
            
        } catch (Exception e) {
            System.err.println("❌ 操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static PrivateKey importECPrivateKeyFromPEM(String keyLabel) throws Exception {
        System.out.println("\n--- 开始从PEM文件导入EC私钥为永久密钥 ---");
        
        String pemFilePath = "../openssl-key/ec_private_key.pem";
        System.out.println("1. 读取PEM文件: " + pemFilePath);
        String pemContent = new String(Files.readAllBytes(Paths.get(pemFilePath)));
        
        System.out.println("2. 从SEC1格式提取私钥值...");
        byte[] keyBytes = parsePEMContent(pemContent);
        byte[] rawKeyBytes = extractPrivateValueFromSEC1(keyBytes);
        System.out.println("   原始密钥字节长度: " + rawKeyBytes.length + " 字节");
        
        System.out.println("3. 创建KeyAttributesMap并设置属性...");
        KeyAttributesMap attributes = new KeyAttributesMap();
        attributes.put(KeyAttribute.KEY_TYPE, KeyType.EC);
        attributes.put(KeyAttribute.EC_PARAMS, EcParams.EC_CURVE_PRIME384);
        attributes.put(KeyAttribute.VALUE, rawKeyBytes);
        attributes.put(KeyAttribute.LABEL, keyLabel);
        attributes.put(KeyAttribute.TOKEN, true);
        attributes.put(KeyAttribute.EXTRACTABLE, false);
        attributes.put(KeyAttribute.SIGN, true);
        attributes.put(KeyAttribute.PRIVATE, true);
        
        System.out.println("4. 导入密钥到CloudHSM...");
        KeyFactory cloudHsmKeyFactory = KeyFactory.getInstance("EC", CloudHsmProvider.PROVIDER_NAME);
        PrivateKey privateKey = cloudHsmKeyFactory.generatePrivate(attributes);
        
        System.out.println("✅ EC私钥导入成功！");
        return privateKey;
    }
    
    private static byte[] parsePEMContent(String pemContent) {
        String cleanContent = pemContent
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(cleanContent);
    }
    
    private static byte[] extractPrivateValueFromSEC1(byte[] sec1Bytes) {
        if (sec1Bytes.length >= 52 && sec1Bytes[3] == 48) {
            byte[] privateKeyBytes = new byte[48];
            System.arraycopy(sec1Bytes, 4, privateKeyBytes, 0, 48);
            return privateKeyBytes;
        }
        
        for (int i = 0; i < sec1Bytes.length - 48; i++) {
            if (sec1Bytes[i] == 0x04 && sec1Bytes[i+1] == 0x30) {
                byte[] privateKeyBytes = new byte[48];
                System.arraycopy(sec1Bytes, i+2, privateKeyBytes, 0, 48);
                return privateKeyBytes;
            }
        }
        
        throw new RuntimeException("无法从SEC1格式中提取私钥值");
    }
    
    public static void validateImportedKey(PrivateKey privateKey) throws Exception {
        System.out.println("\n--- 验证导入的私钥 ---");
        
        Signature signature = Signature.getInstance("SHA256withECDSA", CloudHsmProvider.PROVIDER_NAME);
        signature.initSign(privateKey);
        
        String testMessage = "Hello CloudHSM! Test message for EC private key validation from PEM file.";
        signature.update(testMessage.getBytes("UTF-8"));
        byte[] signatureBytes = signature.sign();
        
        System.out.println("✅ 永久密钥验证成功！");
        System.out.println("   签名长度: " + signatureBytes.length + " 字节");
        System.out.println("   密钥已永久存储在CloudHSM中");
    }
}
