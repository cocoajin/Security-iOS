//
//  NSData+KKSignVerify.m
//  SecurityiOS
//
//  Created by cocoa on 16/12/15.
//  Copyright © 2016年 dev.keke@gmail.com. All rights reserved.
//

#import "NSData+KKSignVerify.h"
#import <Security/Security.h>

@implementation NSData (KKSignVerify)

/**
 根据不同的算法，签名数据，
 */
- (NSData *)signDataWith:(SecKeyRef)privateKey algorithm:(SEC_PKCS1_ALGORITHM )ccAlgorithm
{
    if (!privateKey || self.length <1) {
        return nil;
    }
    
    OSStatus ret;
    NSData *retData = nil;
    size_t siglen = SecKeyGetBlockSize(privateKey);
    uint8_t *sig = malloc(siglen);
    bzero(sig, siglen);
    
    SecPadding secpdal ;
    switch (ccAlgorithm) {
        case SEC_PKCS1SHA1:
            secpdal = kSecPaddingPKCS1SHA1;
            break;
        case SEC_PKCS1SHA224:
            secpdal = kSecPaddingPKCS1SHA224;
            break;
        case SEC_PKCS1SHA256:
            secpdal = kSecPaddingPKCS1SHA256;
            break;
        case SEC_PKCS1SHA384:
            secpdal = kSecPaddingPKCS1SHA384;
            break;
        case SEC_PKCS1SHA512:
            secpdal = kSecPaddingPKCS1SHA512;
            break;
        default:
            secpdal = kSecPaddingPKCS1SHA1;
            break;
    }
    
    ret = SecKeyRawSign(privateKey, secpdal, self.bytes, self.length, sig, &siglen);
    if (ret==errSecSuccess) {
        retData = [NSData dataWithBytes:sig length:siglen];
    }
    
    free(sig);
    sig = NULL;
    
    return retData;
}

/**
 验证签名
 */
- (BOOL)verifySignWith:(SecKeyRef)publicKey signData:(NSData *)signData algorithm:(SEC_PKCS1_ALGORITHM )ccAlgorithm
{
    if (!publicKey || self.length <1) {
        return NO;
    }
    OSStatus ret;
    BOOL retStatus = NO;
    SecPadding secpdal ;
    switch (ccAlgorithm) {
        case SEC_PKCS1SHA1:
            secpdal = kSecPaddingPKCS1SHA1;
            break;
        case SEC_PKCS1SHA224:
            secpdal = kSecPaddingPKCS1SHA224;
            break;
        case SEC_PKCS1SHA256:
            secpdal = kSecPaddingPKCS1SHA256;
            break;
        case SEC_PKCS1SHA384:
            secpdal = kSecPaddingPKCS1SHA384;
            break;
        case SEC_PKCS1SHA512:
            secpdal = kSecPaddingPKCS1SHA512;
            break;
        default:
            secpdal = kSecPaddingPKCS1SHA1;
            break;
    }
    ret = SecKeyRawVerify(publicKey, secpdal, self.bytes, self.length,signData.bytes, signData.length);
    if (ret==errSecSuccess) {
        retStatus = YES;
    }
    return retStatus;
}

@end
