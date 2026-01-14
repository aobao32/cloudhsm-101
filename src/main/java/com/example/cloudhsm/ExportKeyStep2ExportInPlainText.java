package com.example.cloudhsm;

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.KeyStoreWithAttributes;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyReferenceSpec;

import java.io.FileWriter;
import java.security.Key;
import java.security.Security;
import java.util.Base64;

public class ExportKeyStep2ExportInPlainText {
    
    public static void main(String[] args) {
        try {
            Security.addProvider(new CloudHsmProvider());
            
            String hsmUser = System.getenv("HSM_USER");
            String hsmPassword = System.getenv("HSM_PASSWORD");
            
            if (hsmUser == null || hsmPassword == null) {
                System.err.println("错误：请设置环境变量 HSM_USER 和 HSM_PASSWORD");
                System.exit(1);
            }
            
            System.out.println("使用用户: " + hsmUser + " 连接到CloudHSM...");
            
            long keyRefId = 0x0000000000002fddL;
            Key key = findKeyByHandle(keyRefId);
            
            if (key == null) {
                System.err.println("错误：未找到密钥 key-reference: 0x" + Long.toHexString(keyRefId));
                System.exit(1);
            }
            
            byte[] keyBytes = key.getEncoded();
            if (keyBytes == null) {
                System.err.println("错误：无法导出密钥明文，请确认密钥EXTRACTABLE属性为true");
                System.exit(1);
            }
            
            System.out.println("\n密钥导出成功！");
            System.out.println("密钥引用ID: 0x" + Long.toHexString(keyRefId));
            System.out.println("密钥算法: " + key.getAlgorithm());
            System.out.println("密钥格式: " + key.getFormat());
            System.out.println("密钥长度: " + keyBytes.length + " 字节");
            System.out.println("密钥明文 (Base64): " + Base64.getEncoder().encodeToString(keyBytes));
            System.out.println("密钥明文 (Hex): " + bytesToHex(keyBytes));
            
            String pemPath = "../openssl-key/TestKeyForPlainTextExport.pem";
            saveToPEM(keyBytes, pemPath);
            System.out.println("\nPEM文件已保存: " + pemPath);
            
        } catch (Exception e) {
            System.err.println("操作失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static Key findKeyByHandle(long keyHandle) throws Exception {
        KeyStoreWithAttributes keyStore = KeyStoreWithAttributes.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        
        KeyReferenceSpec keyRefSpec = KeyReferenceSpec.getInstance(keyHandle);
        return keyStore.getKey(keyRefSpec);
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private static void saveToPEM(byte[] keyBytes, String path) throws Exception {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyBytes);
        try (FileWriter fw = new FileWriter(path)) {
            fw.write("-----BEGIN PRIVATE KEY-----\n");
            fw.write(base64);
            fw.write("\n-----END PRIVATE KEY-----\n");
        }
    }
}
