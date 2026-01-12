package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyType;
import com.amazonaws.cloudhsm.jce.provider.attributes.EcParams;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * 使用KeyAttributesMap方式导入EC私钥到CloudHSM
 * 支持设置自定义标签和永久密钥属性
 */
public class ECPrivateKeyImport {
    
    // EC私钥PEM格式（PKCS#8格式，CloudHSM要求）
    private static final String EC_PRIVATE_KEY_PEM = 
            "-----BEGIN PRIVATE KEY-----\n" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n" +
            "-----END PRIVATE KEY-----";
    
    public static void main(String[] args) {
        try {
            // 加载CloudHSM JCE Provider
            Security.addProvider(new CloudHsmProvider());
            
            // 检查环境变量
            String hsmUser = System.getenv("HSM_USER");
            String hsmPassword = System.getenv("HSM_PASSWORD");
            
            if (hsmUser == null || hsmPassword == null) {
                System.err.println("错误：请设置环境变量 HSM_USER 和 HSM_PASSWORD");
                System.err.println("示例：");
                System.err.println("export HSM_USER=your_cu_username");
                System.err.println("export HSM_PASSWORD=your_cu_password");
                System.exit(1);
            }
            
            System.out.println("=== CloudHSM EC私钥导入演示（永久密钥+自定义标签）===");
            System.out.println("使用用户: " + hsmUser + " 连接到CloudHSM...");
            
            // 设置密钥标签
            String keyLabel = "myImportedPrivateKey";
            System.out.println("密钥标签: " + keyLabel);
            
            // 导入EC私钥为永久密钥
            PrivateKey importedKey = importECPrivateKeyAsPermanent(keyLabel);
            
            // 验证导入的密钥
            validateImportedKey(importedKey);
            
            System.out.println("\n✅ EC私钥永久导入成功完成！");
            System.out.println("密钥已作为永久密钥存储在CloudHSM中，标签为: " + keyLabel);
            
        } catch (Exception e) {
            System.err.println("❌ 操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 从PEM格式字符串导入EC私钥到CloudHSM作为永久密钥
     * 使用KeyAttributesMap设置自定义标签和属性
     * 
     * @param keyLabel 自定义密钥标签
     * @return 导入的私钥对象
     * @throws Exception 导入失败时抛出异常
     */
    public static PrivateKey importECPrivateKeyAsPermanent(String keyLabel) throws Exception {
        System.out.println("\n--- 开始导入EC私钥为永久密钥 ---");
        
        // 步骤1：解析PEM格式，提取PKCS8数据
        System.out.println("1. 解析PEM格式...");
        byte[] pkcs8Bytes = parsePEMContent(EC_PRIVATE_KEY_PEM);
        System.out.println("   PEM解析完成，PKCS8数据长度: " + pkcs8Bytes.length + " 字节");
        
        // 步骤2：使用标准JCE解析密钥以提取原始密钥字节
        System.out.println("2. 解析PKCS8格式获取密钥参数...");
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        KeyFactory standardKeyFactory = KeyFactory.getInstance("EC");
        ECPrivateKey ecKey = (ECPrivateKey) standardKeyFactory.generatePrivate(pkcs8Spec);
        
        // 步骤3：提取原始密钥字节
        System.out.println("3. 提取原始密钥字节...");
        byte[] rawKeyBytes = extractRawKeyBytes(ecKey);
        System.out.println("   原始密钥字节长度: " + rawKeyBytes.length + " 字节");
        
        // 步骤4：创建KeyAttributesMap并设置属性
        System.out.println("4. 创建KeyAttributesMap并设置完整属性...");
        KeyAttributesMap attributes = new KeyAttributesMap();
        
        // 必需属性
        attributes.put(KeyAttribute.KEY_TYPE, KeyType.EC);           // EC密钥类型
        attributes.put(KeyAttribute.EC_PARAMS, EcParams.EC_CURVE_PRIME384); // P-384曲线参数
        attributes.put(KeyAttribute.VALUE, rawKeyBytes);             // 密钥字节数据
        attributes.put(KeyAttribute.LABEL, keyLabel);                // 密钥标签
        
        // 存储属性
        attributes.put(KeyAttribute.TOKEN, true);                    // 永久密钥（持久化存储）
        attributes.put(KeyAttribute.EXTRACTABLE, false);             // 不可提取（安全）
        
        // 用途属性
        attributes.put(KeyAttribute.SIGN, true);                     // 允许签名
        attributes.put(KeyAttribute.PRIVATE, true);                  // 私有密钥
        
        System.out.println("   ✓ 密钥类型: EC");
        System.out.println("   ✓ 曲线参数: prime384v1 (P-384)");
        System.out.println("   ✓ 密钥标签: " + keyLabel);
        System.out.println("   ✓ 永久存储: true");
        System.out.println("   ✓ 可提取: false");
        System.out.println("   ✓ 允许签名: true");
        System.out.println("   ✓ 私有密钥: true");
        
        // 步骤5：使用CloudHSM KeyFactory导入密钥
        System.out.println("5. 导入密钥到CloudHSM...");
        KeyFactory cloudHsmKeyFactory = KeyFactory.getInstance("EC", CloudHsmProvider.PROVIDER_NAME);
        PrivateKey privateKey = cloudHsmKeyFactory.generatePrivate(attributes);
        
        System.out.println("✅ EC私钥导入成功！");
        System.out.println("   密钥算法: " + privateKey.getAlgorithm());
        System.out.println("   密钥格式: " + privateKey.getFormat());
        System.out.println("   密钥类: " + privateKey.getClass().getSimpleName());
        
        return privateKey;
    }
    
    /**
     * 解析PEM格式内容，提取Base64编码的密钥数据
     * 
     * @param pemContent PEM格式的密钥字符串
     * @return 解码后的密钥字节数组
     */
    private static byte[] parsePEMContent(String pemContent) {
        // 移除PEM头尾标记和所有空白字符
        String cleanContent = pemContent
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
        
        // Base64解码
        return Base64.getDecoder().decode(cleanContent);
    }
    
    /**
     * 从ECPrivateKey提取原始密钥字节
     * 
     * @param ecPrivateKey EC私钥对象
     * @return 原始密钥字节数组
     */
    private static byte[] extractRawKeyBytes(ECPrivateKey ecPrivateKey) {
        // 获取私钥值（大整数）
        BigInteger privateValue = ecPrivateKey.getS();
        
        // 转换为字节数组
        byte[] privateBytes = privateValue.toByteArray();
        
        // 如果字节数组长度超过32字节（P-256）或48字节（P-384），可能包含符号位
        // 需要移除多余的符号位字节
        if (privateBytes.length > 32 && privateBytes[0] == 0) {
            byte[] trimmedBytes = new byte[privateBytes.length - 1];
            System.arraycopy(privateBytes, 1, trimmedBytes, 0, trimmedBytes.length);
            return trimmedBytes;
        }
        
        // 如果字节数组长度不足32字节，需要在前面补零
        if (privateBytes.length < 32) {
            byte[] paddedBytes = new byte[32];
            System.arraycopy(privateBytes, 0, paddedBytes, 32 - privateBytes.length, privateBytes.length);
            return paddedBytes;
        }
        
        return privateBytes;
    }
    
    /**
     * 验证导入的私钥是否正常工作
     * 通过执行签名操作来测试密钥功能
     * 
     * @param privateKey 要验证的私钥
     * @throws Exception 验证失败时抛出异常
     */
    public static void validateImportedKey(PrivateKey privateKey) throws Exception {
        System.out.println("\n--- 验证导入的私钥 ---");
        
        try {
            // 创建签名对象
            System.out.println("1. 创建ECDSA签名对象...");
            Signature signature = Signature.getInstance("SHA256withECDSA", CloudHsmProvider.PROVIDER_NAME);
            
            // 初始化签名
            System.out.println("2. 初始化签名操作...");
            signature.initSign(privateKey);
            
            // 准备测试数据
            String testMessage = "Hello CloudHSM! This is a test message for EC private key validation.";
            System.out.println("3. 准备测试数据: " + testMessage);
            
            // 执行签名
            System.out.println("4. 执行签名操作...");
            signature.update(testMessage.getBytes("UTF-8"));
            byte[] signatureBytes = signature.sign();
            
            // 输出结果
            System.out.println("✅ 永久密钥验证成功！");
            System.out.println("   测试消息: " + testMessage);
            System.out.println("   签名长度: " + signatureBytes.length + " 字节");
            System.out.println("   签名算法: SHA256withECDSA");
            System.out.println("   签名数据: " + bytesToHex(signatureBytes, 32) + "...");
            System.out.println("   密钥已永久存储在CloudHSM中");
            
        } catch (Exception e) {
            System.err.println("❌ 私钥验证失败: " + e.getMessage());
            throw e;
        }
    }
    
    /**
     * 将字节数组转换为十六进制字符串（用于显示）
     * 
     * @param bytes 字节数组
     * @param maxLength 最大显示长度
     * @return 十六进制字符串
     */
    private static String bytesToHex(byte[] bytes, int maxLength) {
        StringBuilder result = new StringBuilder();
        int length = Math.min(bytes.length, maxLength);
        
        for (int i = 0; i < length; i++) {
            result.append(String.format("%02x", bytes[i]));
        }
        
        return result.toString();
    }
}