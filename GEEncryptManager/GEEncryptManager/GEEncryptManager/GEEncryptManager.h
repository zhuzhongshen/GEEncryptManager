//
//  GEEncryptManager.h
//  GEEncryptManager
//
//  Created by goldeneye on 2017/10/30.
//  Copyright © 2017年 goldeneye by smart-small. All rights reserved.
//

#import <Foundation/Foundation.h>

#define encrytKey @"GEEncryptManager"

/* rsa key*/
#define RSA_PublicKey @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIqovlSAt+gtPtgONnS9JQvbJQSdhEdDRfgxqa4wJLbZwGmq2FQlD+1hOnHzcKt2jxQtjnRZUN8ts0/xGHMoKN85tQwq9CQM3LXVxg6XEybcHbbN/UQlqDrgFd7eVO+YdynSlmnEvAS+LPnVH2Y+Q4nj4CR0qqr3qwBDXR2F421wIDAQAB"
#define RSA_PrivateKey @"MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMiqi+VIC36C0+2A42dL0lC9slBJ2ER0NF+DGprjAkttnAaarYVCUP7WE6cfNwq3aPFC2OdFlQ3y2zT/EYcygo3zm1DCr0JAzctdXGDpcTJtwdts39RCWoOuAV3t5U75h3KdKWacS8BL4s+dUfZj5DiePgJHSqqverAENdHYXjbXAgMBAAECgYEAnwAL83Q/r1HIzUM4bQv2LQXyeY3ZsHwHV7sRZLMFiXDjlZQQdCvU8+f7EIw6V+J2Y9zc83v+HFxXd0m4wNC0ApEYjm2+k8TMPb1zsCsZprK04zfrJZ7IfT0UG3ih4h3g/f5QvVOw9HsjLMsHEhGcPt2v9BByePFJq6tUm3qQOZECQQDrY24fbp6IiCOjR6O9e6/u92xYoHqp5r3d+RdtHnroqZeMoSFfMaCWPIZkIXy3mKU3irOnJr5z8nYcQ8iq78u5AkEA2jzEpfBwWrMI/RMyoqKbLVPlpFWGytbaFMliFOfiTKZdznbeuKB5nnOaXzk3Ic41WwXItxdC2HRrHsxN1YT/DwJBAM/6BUXOZlJ5/wr4dEsqKtN4V4mjGV5e2mly+ejW4oAJwDZn8+V5Iss7ZP65u8k4HNqLOZq5l9M4anUkyvuFbjkCQQCF0aFbhzW9x+6JEE6KP18bykgUHoWKt3f+KwZDf3TaP2FiCq3DVFN+/6/3F+RgjEtXRxKugkrw42IT/n7zoJutAkBSywHknZuaJNhr9c4dCQhRYoFYYNZyh9jJ+b8WxL3Et24v3sRneoX/uE8WcE+vP2WBqqTaftGMya51lvhps7LW"




typedef enum : NSUInteger {
    GEEncrytShaTypeSha1,
    GEEncrytShaTypeSha224,
    GEEncrytShaTypeSha256,
    GEEncrytShaTypeSha384, 
    GEEncrytShaTypeSha512
} GEEncrytShaType;

typedef enum : NSUInteger {
    GEEncrytHmacTypeSha1,
    GEEncrytHmacTypeSha224, //warning
    GEEncrytHmacTypeSha256,
    GEEncrytHmacTypeSha384, //warning
    GEEncrytHmacTypeSha512,
    GEEncrytHmacTypeShaMD5,
} GEEncrytHmacType;

@interface GEEncryptManager : NSObject

//md5加密方法
+ (NSString *)ge_md5EncrypWithString:(NSString *)string;

/*** Sha加密 ****/
/*
 type   GEEncrytShaType枚举中
 string 需要加密的字符串
 */
+ (NSString *)ge_SHAWithType:(GEEncrytShaType)type encryptWithString:(NSString *)string;
/*** HMAC加密 ***/
/*
 type   GEEncrytHmacType枚举中
 string 需要加密的字符串
 key    加密key
 */
+ (NSString *)ge_HmacShaWithType:(GEEncrytHmacType)type encryptWithString:(NSString *)string withKey:(NSString *)key;

/*** DES加解密 ***/
/*
 * DES加密
 * string需要加密的字符串
 * key 加密password
 * iv默认{1,2,3,4,5,6,7,8} 需自行修改
 */
+ (NSString *)ge_DESEncryptWithString:(NSString *)string withKey:(NSString *)key;
/*
 * DES解密
 * string需要接密的字符串
 * key 解密password
 * iv默认{1,2,3,4,5,6,7,8} 需自行修改
 */
+ (NSString *)ge_DESDecryptWithString:(NSString *)string withKey:(NSString *)key;

/*** AES加解密 ***/
/*
 * AES加密
 * string需要接密的字符串
 * password 加密password
 */
+ (NSString *)ge_AESEncryptWithString:(NSString *)string witkPassword:(NSString *)password;
/*
 * AES解密
 * string需要解密的字符串
 * password 解密password
 */
+ (NSString *)ge_AESDecryptWithString:(NSString *)string witkPassword:(NSString *)password;
/*** RSA加、解密 ***/
/*
 *  公钥加密方法
 *
 *  @param str    需要加密的字符串
 *  @param pubKey 公钥字符串
 */
+ (NSString *)ge_RSAEncryptWithString:(NSString *)string withPublicKey:(NSString *)publicKey;
/*
 *  私钥解密方法
 *
 *  @param str    需要解密的字符串
 *  @param pubKey 私钥字符串
 */
+ (NSString *)ge_RSADecryptWithString:(NSString *)string withPrivateKey:(NSString *)privateKey;
/*
 *   '.der'格式的公钥加密方法
 *
 *  @param string   需要加密的字符串
 *  @param fileName  '.der'格式的公钥文件名字
 */
+ (NSString *)ge_RSAEncryptWithString:(NSString *)string publicKeyWithContentOfFileName:(NSString *)fileName;
/**
 *   '.p12'格式的私钥解密方法
 *
 *  @param string       需要解密的字符串
 *  @param fileName      '.p12'格式的私钥文件名字
 *  @param password  私钥文件密码
 */
+ (NSString *)ge_RSADecryptWithString:(NSString *)string privateKeyWithContentsOfFileName:(NSString *)fileName password:(NSString *)password;
@end
