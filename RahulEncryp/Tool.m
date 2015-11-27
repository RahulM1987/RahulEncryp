//
//  Tool.m
//  
//
//  Created by Rahul on 8/27/15.
//  Copyright (c) 2015 Rahul. All rights reserved.
//

#import "Tool.h"

#define kCryptingKey @"696cfcba471012bd"  /// 同上
#define kCryptingIv @"16b7013901a906ea"   /// 同上

@implementation Tool

+ (NSString*) crypt:(NSString*)recource
{
    NSData *data = [recource dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encrypt = [self AES128EncryptWithKey:kCryptingKey withData:data iv:kCryptingIv];
    return [self stringWithHexBytes:encrypt];
}

+ (NSString*) decryptData:(NSData*)recource
{
    NSData *decrypt = [self AES128DecryptWithKey:kCryptingKey withData:recource iv:kCryptingIv];
    return [[NSString alloc] initWithData:decrypt encoding:NSUTF8StringEncoding];
}

+ (NSString*) decrypt:(NSString*)recource
{
    NSData* data=[self decodeFromHexidecimal:recource];
    NSData *decrypt = [self AES128DecryptWithKey:kCryptingKey withData:data iv:kCryptingIv];
    return [[NSString alloc] initWithData:decrypt encoding:NSUTF8StringEncoding];
}

+ (NSData *) decodeFromHexidecimal:(NSString*)str
{
    NSString *command = [NSString stringWithString:str];
    command = [command stringByReplacingOccurrencesOfString:@" " withString:@""];
    NSMutableData *commandToSend = [[NSMutableData data] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    int i;
    for (i=0; i < [command length]/2; i++) {
        byte_chars[0] = [command characterAtIndex:i*2];
        byte_chars[1] = [command characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [commandToSend appendBytes:&whole_byte length:1];
    }
    return commandToSend;
}

+ (NSData *)AES128EncryptWithKey:(NSString *)key withData:(NSData*)_data iv:(NSString *) iv
{
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof( keyPtr ) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [_data length];
    
    int diff = kCCKeySizeAES128 - (dataLength % kCCKeySizeAES128);
    unsigned long int newSize = 0;
    
    if(diff > 0)
    {
        newSize = dataLength + diff;
    }
    
    char dataPtr[newSize];
    memcpy(dataPtr, [_data bytes], [_data length]);
    for(int i = 0; i < diff; i++)
    {
        dataPtr[i + dataLength] = 0x00;
    }
    
    size_t bufferSize = newSize + kCCBlockSizeAES128;
    
    void *buffer = malloc( bufferSize );
    memset(buffer, 0, bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt( kCCEncrypt, kCCAlgorithmAES128, 0x0000,
                                          keyPtr, kCCKeySizeAES128,
                                          ivPtr,
                                          dataPtr,
                                          sizeof(dataPtr),
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted );
    if( cryptStatus == kCCSuccess )
    {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free( buffer ); //free the buffer
    return nil;
}

+ (NSData *)AES128DecryptWithKey:(NSString *)key withData:(NSData*)data iv:(NSString *) iv
{
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128,  0x0000,
                                          keyPtr, kCCBlockSizeAES128,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer); //free the buffer;
    return nil;
}

+ (NSString*) stringWithHexBytes:(NSData*)_data {
    NSMutableString *stringBuffer = [NSMutableString stringWithCapacity:([_data length] * 2)];
    const unsigned char *dataBuffer = [_data bytes];
    int i;
    for (i = 0; i < [_data length]; ++i) {
        [stringBuffer appendFormat:@"%02lX", (unsigned long)dataBuffer[i]];
    }
    return [stringBuffer copy];
}


+ (NSString *)sha1:(NSString *)str {
    const char *cStr = [str UTF8String];
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(cStr, (unsigned int)strlen(cStr), result);
    NSString * strreturn = [NSString  stringWithFormat:
         @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
         result[0], result[1], result[2], result[3], result[4],
         result[5], result[6], result[7],
         result[8], result[9], result[10], result[11], result[12],
         result[13], result[14], result[15],
         result[16], result[17], result[18], result[19]
         ];
    return strreturn;
}

@end
