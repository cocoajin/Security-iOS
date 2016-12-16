//
//  ViewController.m
//  SecurityiOS
//
//  Created by cocoa on 16/12/14.
//  Copyright © 2016年 dev.keke@gmail.com. All rights reserved.
//

#import "ViewController.h"
#import <CommonCrypto/CommonCrypto.h>
#import "NSData+KKHASH.h"
#import "NSData+KKSignVerify.h"
#import "NSData+KKRSA.h"
#import "NSData+KKAES.h"
#import "SecKeyTools.h"

@interface ViewController ()

@end

@implementation ViewController

//生成RSA密钥对，公钥和私钥，支持的SIZE有
// sizes for RSA keys are: 512, 768, 1024, 2048.
- (void)generateRSAKeyPair:(int )keySize
{
    if (publicKeyRef) {
        return;
    }
    OSStatus ret = 0;
    publicKeyRef = NULL;
    privateKeyRef = NULL;
    ret = SecKeyGeneratePair((CFDictionaryRef)@{(id)kSecAttrKeyType:(id)kSecAttrKeyTypeRSA,(id)kSecAttrKeySizeInBits:@(keySize)}, &publicKeyRef, &privateKeyRef);
    NSAssert(ret==errSecSuccess, @"密钥对生成失败：%d",ret);
    
    NSLog(@"%@",publicKeyRef);
    NSLog(@"%@",privateKeyRef);
    NSLog(@"max size:%lu",SecKeyGetBlockSize(privateKeyRef));
    
}

//公钥加密私钥密钥测试
/** 三种填充方式区别
 kSecPaddingNone      = 0,   要加密的数据块大小<＝SecKeyGetBlockSize的大小，如这里128
 kSecPaddingPKCS1     = 1,   要加密的数据块大小<=128-11
 kSecPaddingOAEP      = 2,   要加密的数据块大小<=128-42
  密码学中的设计原则，一般用RSA来加密 对称密钥，用对称密钥加密大量的数据
  非对称加密速度慢，对称加密速度快
 */
- (void)testRSAEncryptAndDecrypt
{
    [self generateRSAKeyPair:kRSA_KEY_SIZE];

    NSData *srcData = [@"0123456789" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"%@",srcData);
    uint8_t encData[kRSA_KEY_SIZE/8] = {0};
    uint8_t decData[kRSA_KEY_SIZE/8] = {0};
    size_t blockSize = kRSA_KEY_SIZE / 8 ;
    OSStatus ret;
    
    
    ret = SecKeyEncrypt(publicKeyRef, kSecPaddingNone, srcData.bytes, srcData.length, encData, &blockSize);
    NSAssert(ret==errSecSuccess, @"加密失败");
    
    
    ret = SecKeyDecrypt(privateKeyRef, kSecPaddingNone, encData, blockSize, decData, &blockSize);
    NSAssert(ret==errSecSuccess, @"解密失败");
    
    NSData *dedData = [NSData dataWithBytes:decData length:blockSize];
    NSLog(@"dec:%@",dedData);
    if (memcmp(srcData.bytes, dedData.bytes, srcData.length)==0) {
        NSLog(@"PASS");
    }
}


//测试哈希函数
- (void)testKKHASHTools
{
    //以下结果由openssl dtsg 命令得出的结果，并和这里相比对
    NSString *tpath = [[NSBundle mainBundle] pathForResource:@"src.txt" ofType:nil];
    NSData *test = [NSData dataWithContentsOfFile:tpath];
    NSLog(@"%@",[[test hashDataWith:CCDIGEST_MD2] hexString]);
    if([[[test hashDataWith:CCDIGEST_MD4] hexString] isEqualToString:@"a695ea9f14a89c4e82ca5cf52a28d45d"])
    {
        NSLog(@"MD4 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_MD5] hexString] isEqualToString:@"781e5e245d69b566979b86e28d23f2c7"])
    {
        NSLog(@"MD5 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA1] hexString] isEqualToString:@"87acec17cd9dcd20a716cc2cf67417b71c8a7016"])
    {
        NSLog(@"SHA1 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA224] hexString] isEqualToString:@"f28ad8ecd48ba6f914c114821685ad08f0d6103649ff156599a90426"])
    {
        NSLog(@"SHA224 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA256] hexString] isEqualToString:@"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882"])
    {
        NSLog(@"SHA256 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA384] hexString] isEqualToString:@"90ae531f24e48697904a4d0286f354c50a350ebb6c2b9efcb22f71c96ceaeffc11c6095e9ca0df0ec30bf685dcf2e5e5"])
    {
        NSLog(@"SHA384 TEST PASS");
    }
    if([[[test hashDataWith:CCDIGEST_SHA512] hexString] isEqualToString:@"bb96c2fc40d2d54617d6f276febe571f623a8dadf0b734855299b0e107fda32cf6b69f2da32b36445d73690b93cbd0f7bfc20e0f7f28553d2a4428f23b716e90"])
    {
        NSLog(@"SHA512 TEST PASS");
    }

}

/**
    签名与验证签名
 */

- (void)testSignAndVerify
{
    [self generateRSAKeyPair:kRSA_KEY_SIZE];

    
    NSString *tpath = [[NSBundle mainBundle] pathForResource:@"src.txt" ofType:nil];
    NSData *ttDt = [NSData dataWithContentsOfFile:tpath];
    NSData *sha1dg = [ttDt hashDataWith:CCDIGEST_SHA1];
    
    OSStatus ret;
    
    
    //私钥签名，公钥验证签名
    size_t siglen = SecKeyGetBlockSize(privateKeyRef);
    uint8_t *sig = malloc(siglen);
    bzero(sig, siglen);
    ret = SecKeyRawSign(privateKeyRef, kSecPaddingPKCS1SHA256, sha1dg.bytes, sha1dg.length, sig, &siglen);
    NSAssert(ret==errSecSuccess, @"签名失败");
    
    
    ret = SecKeyRawVerify(publicKeyRef, kSecPaddingPKCS1SHA256, sha1dg.bytes, sha1dg.length,sig, siglen);
    NSAssert(ret==errSecSuccess, @"验证签名失败");
    
    if (ret==errSecSuccess) {
        NSLog(@"SIGN VERIFY PASS");
    }
}


//测试签名与验证签名工具
- (void)testkksignVerifyTools
{
    [self generateRSAKeyPair:kRSA_KEY_SIZE];
    
    NSString *tpath = [[NSBundle mainBundle] pathForResource:@"src.txt" ofType:nil];
    NSData *ttDt = [NSData dataWithContentsOfFile:tpath];
    NSData *sha1dg = [ttDt hashDataWith:CCDIGEST_MD4];
    

    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA1] algorithm:SEC_PKCS1SHA1]) {
        NSLog(@"SIGN-VERIFY sha1 PASS");
    }
    
    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA224] algorithm:SEC_PKCS1SHA224]) {
        NSLog(@"SIGN-VERIFY sha224 PASS");
    }
    
    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA256] algorithm:SEC_PKCS1SHA256]) {
        NSLog(@"SIGN-VERIFY sha256 PASS");
    }
    
    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA384] algorithm:SEC_PKCS1SHA384]) {
        NSLog(@"SIGN-VERIFY sha384 PASS");
    }
    if ([sha1dg verifySignWith:publicKeyRef signData:[sha1dg signDataWith:privateKeyRef algorithm:SEC_PKCS1SHA512] algorithm:SEC_PKCS1SHA512]) {
        NSLog(@"SIGN-VERIFY sha512 PASS");
    }
    
    
}

- (void)testKKRSATools
{
    [self generateRSAKeyPair:kRSA_KEY_SIZE];
    NSData *srcData = [@"01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567" dataUsingEncoding:NSASCIIStringEncoding];
    //max 128
    NSData *decData = [[srcData RSAEncryptWith:publicKeyRef paddingType:RSAPaddingNONE] RSADecryptWith:privateKeyRef paddingType:RSAPaddingNONE];
    
    if (memcmp(srcData.bytes, decData.bytes, srcData.length)==0) {
        NSLog(@"RSA RSAPaddingNONE TEST PASS");
    }
    
    
    NSData *srcData2 = [@"012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456" dataUsingEncoding:NSASCIIStringEncoding];
    //max 128-11 117
    NSData *decData2 = [[srcData2 RSAEncryptWith:publicKeyRef paddingType:RSAPaddingPKCS1]
                        RSADecryptWith:privateKeyRef paddingType:RSAPaddingPKCS1];
    
    if (memcmp(srcData2.bytes, decData2.bytes, srcData2.length)==0) {
        NSLog(@"RSA RSAPaddingPKCS1 TEST PASS");
    }
    
    
    NSData *srcData3 = [@"01234567890123456789012345678901234567890123456789012345678901234567890123456789123456" dataUsingEncoding:NSASCIIStringEncoding];
    //max 128-42 86
    NSData *decData3 = [[srcData3 RSAEncryptWith:publicKeyRef paddingType:RSAPaddingOAEP] RSADecryptWith:privateKeyRef paddingType:RSAPaddingOAEP];
    
    if (memcmp(srcData3.bytes, decData3.bytes, srcData3.length)==0) {
        NSLog(@"RSA RSAPaddingOAEP TEST PASS");
    }
    
    

}


- (void)testAESKKTools
{
    NSData *key16 = [@"0123456789123456" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key24 = [@"012345678901234567891234" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key32 = [@"01234567890123456789012345678912" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *iv16 = [@"0123456789654321" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *srcData = [@"this is src test data" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"%@",srcData);
    
    
    
    NSData *dec16 = [[srcData AES_CBC_EncryptWith:key16 iv:iv16] AES_CBC_DecryptWith:key16 iv:iv16];
    if (memcmp(srcData.bytes, dec16.bytes, srcData.length)==0) {
        NSLog(@"AES_cbc_16 PASS");
    }
    
    
    NSData *dec24 = [[srcData AES_CBC_EncryptWith:key24 iv:iv16] AES_CBC_DecryptWith:key24 iv:iv16];
    if (memcmp(srcData.bytes, dec24.bytes, srcData.length)==0) {
        NSLog(@"AES_cbc_24 PASS");
    }
    
    
    NSData *dec32 = [[srcData AES_CBC_EncryptWith:key32 iv:iv16] AES_CBC_DecryptWith:key32 iv:iv16];
    if (memcmp(srcData.bytes, dec32.bytes, srcData.length)==0) {
        NSLog(@"AES_cbc_32 PASS");
    }
    
    
    
    
    NSData *edec16 = [[srcData AES_ECB_EncryptWith:key16] AES_ECB_DecryptWith:key16];
    if (memcmp(srcData.bytes, edec16.bytes, srcData.length)==0) {
        NSLog(@"AES_ecb_16 PASS");
    }
    
    
    NSData *edec24 = [[srcData AES_ECB_EncryptWith:key24] AES_ECB_DecryptWith:key24];
    if (memcmp(srcData.bytes, edec24.bytes, srcData.length)==0) {
        NSLog(@"AES_ecb_24 PASS");
    }
    
    
    NSData *edec32 = [[srcData AES_ECB_EncryptWith:key32] AES_ECB_DecryptWith:key32];
    if (memcmp(srcData.bytes, edec32.bytes, srcData.length)==0) {
        NSLog(@"AES_ecb_32 PASS");
    }
    
    
    
}

- (void)testReadKeyFromFiles
{
    NSString *cerPA = [[NSBundle mainBundle] pathForResource:@"CPPUB.cer" ofType:nil];
    NSString *p12PA = [[NSBundle mainBundle] pathForResource:@"CPPRI.p12" ofType:nil];
    
    SecKeyRef pubkey = [SecKeyTools publicKeyFromCer:cerPA];
    SecKeyRef prikey = [SecKeyTools privateKeyFromP12:p12PA password:@"test"];

    NSLog(@"%@",pubkey);
    NSLog(@"%@",prikey);
    
    NSLog(@"%lu",SecKeyGetBlockSize(prikey));
    
    
    NSData *srcData = [@"0123456789" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"%@",srcData);
    NSData *encDT = [srcData RSAEncryptWith:pubkey paddingType:RSAPaddingPKCS1];
    NSData *decDT = [encDT RSADecryptWith:prikey paddingType:RSAPaddingPKCS1];
    NSLog(@"%@",decDT);
    
    
    
    NSString *pripem = [[NSBundle mainBundle] pathForResource:@"private.pem" ofType:nil];
    NSString *pubpem = [[NSBundle mainBundle] pathForResource:@"public.pem" ofType:nil];
    SecKeyRef pubKK = [SecKeyTools publicKeyFromPem:pubpem keySize:kRSA_KEY_SIZE];
    SecKeyRef priKK = [SecKeyTools privaKeyFromPem:pripem keySize:kRSA_KEY_SIZE];
    NSLog(@"%@",pubKK);
    NSLog(@"%@",priKK);
    
    NSLog(@"%lu",SecKeyGetBlockSize(priKK));
    NSData *srcData2 = [@"0123456789" dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"%@",srcData2);
    NSData *encDT2 = [srcData2 RSAEncryptWith:pubKK paddingType:RSAPaddingPKCS1];
    NSData *decDT2 = [encDT2 RSADecryptWith:priKK paddingType:RSAPaddingPKCS1];
    NSLog(@"%@",decDT2);
    
    
}

- (void)viewDidLoad {
    [super viewDidLoad];

    
    [self generateRSAKeyPair:kRSA_KEY_SIZE];
    
    [self testRSAEncryptAndDecrypt];
    [self testKKHASHTools];
    [self testSignAndVerify];
    [self testkksignVerifyTools];

    [self testKKRSATools];
    [self testAESKKTools];
    
    [self testReadKeyFromFiles];
    
    
    


    
}





- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
