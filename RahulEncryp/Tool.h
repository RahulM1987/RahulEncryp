//
//  Tool.h
//  
//
//  Created by Rahul on 8/27/15.
//  Copyright (c) 2015 Rahul. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "CommonCrypto/CommonCrypto.h"

@interface Tool : NSObject

+ (NSString*) crypt:(NSString*)recource;
+ (NSString*) decrypt:(NSString*)recource;
+ (NSString *)sha1:(NSString *)str;

@end
