//
//  SecKeyTools.m
//  SecurityiOS
//
//  Created by cocoa on 16/12/16.
//  Copyright © 2016年 dev.keke@gmail.com. All rights reserved.
//

#import "SecKeyTools.h"

@implementation SecKeyTools

/**
 从x509 cer证书中读取公钥
 */
+ (SecKeyRef )publicKeyFromCer:(NSString *)cerFile
{
    OSStatus            err;
    NSData *            certData;
    SecCertificateRef   cert;
    SecPolicyRef        policy;
    SecTrustRef         trust;
    SecTrustResultType  trustResult;
    SecKeyRef           publicKeyRef;
    
    certData = [NSData dataWithContentsOfFile:cerFile];
    cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef) certData);
    policy = SecPolicyCreateBasicX509();
    err = SecTrustCreateWithCertificates(cert, policy, &trust);
    NSAssert(err==errSecSuccess,@"证书加载失败");
    err = SecTrustEvaluate(trust, &trustResult);
    NSAssert(err==errSecSuccess,@"公钥加载失败");
    publicKeyRef = SecTrustCopyPublicKey(trust);
    
    CFRelease(policy);
    CFRelease(cert);
    return publicKeyRef;
}



/**
 从 p12 文件中读取私钥，一般p12都有密码
 */
+ (SecKeyRef )privateKeyFromP12:(NSString *)p12File password:(NSString *)pwd

{
    NSData *            pkcs12Data;
    CFArrayRef          imported;
    NSDictionary *      importedItem;
    SecIdentityRef      identity;
    OSStatus            err;
    SecKeyRef           privateKeyRef;

    pkcs12Data = [NSData dataWithContentsOfFile:p12File];
    err = SecPKCS12Import((__bridge CFDataRef)pkcs12Data,(__bridge CFDictionaryRef) @{(__bridge NSString *)kSecImportExportPassphrase:pwd}, &imported);
    NSAssert(err==errSecSuccess,@"p12加载失败");
    importedItem = (__bridge NSDictionary *) CFArrayGetValueAtIndex(imported, 0);
    identity = (__bridge SecIdentityRef) importedItem[(__bridge NSString *) kSecImportItemIdentity];
    
    err = SecIdentityCopyPrivateKey(identity, &privateKeyRef);
    NSAssert(err==errSecSuccess,@"私钥加载失败");
    CFRelease(imported);
    
    
    return privateKeyRef;
}


+ (SecKeyRef )publicKeyFromPem:(NSString *)pemFile keySize:(size_t )size
{
    SecKeyRef pubkeyref;
    NSError *readFErr = nil;
    CFErrorRef errref = noErr;
    NSString *pemStr = [NSString stringWithContentsOfFile:pemFile encoding:NSASCIIStringEncoding error:&readFErr];
    NSAssert(readFErr==nil, @"pem文件加载失败");
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
    NSData *dataPubKey = [[NSData alloc]initWithBase64EncodedString:pemStr options:0];

    NSMutableDictionary *dicPubkey = [[NSMutableDictionary alloc]initWithCapacity:1];
    [dicPubkey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [dicPubkey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)kSecAttrKeyClass];
    [dicPubkey setObject:@(size) forKey:(__bridge id)kSecAttrKeySizeInBits];

    pubkeyref = SecKeyCreateWithData((__bridge CFDataRef)dataPubKey, (__bridge CFDictionaryRef)dicPubkey, &errref);

    NSAssert(errref==noErr, @"公钥加载错误");
    
    return pubkeyref;
}

+ (SecKeyRef )privaKeyFromPem:(NSString *)pemFile keySize:(size_t )size
{
    SecKeyRef prikeyRef;
    NSError *readFErr = nil;
    CFErrorRef err = noErr;
    
    NSString *pemStr = [NSString stringWithContentsOfFile:pemFile encoding:NSASCIIStringEncoding error:&readFErr];
    NSAssert(readFErr==nil, @"pem文件加载失败");
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"-----BEGIN RSA PRIVATE KEY-----" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    pemStr = [pemStr stringByReplacingOccurrencesOfString:@"-----END RSA PRIVATE KEY-----" withString:@""];
    NSData *pemData = [[NSData alloc]initWithBase64EncodedString:pemStr options:0];
    
    NSMutableDictionary *dicPrikey = [[NSMutableDictionary alloc]initWithCapacity:1];
    [dicPrikey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [dicPrikey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [dicPrikey setObject:@(size) forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    prikeyRef = SecKeyCreateWithData((__bridge CFDataRef)pemData, (__bridge CFDictionaryRef)dicPrikey, &err);
    NSAssert(err==noErr, @"私钥加载错误");
    
    
    return prikeyRef;
}

@end
