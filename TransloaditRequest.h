//
//  TransloaditRequest.h
//

#import <Foundation/Foundation.h>
#import "ASIFormDataRequest.h"

@interface TransloaditRequest : ASIFormDataRequest {
    NSString *secret;
	NSMutableDictionary *params;
}

@property(nonatomic, retain) NSMutableDictionary *params;

- (id)initWithCredentials:(NSString *)key secret:(NSString *)secret;
- (void)signRequest;

+ (NSData *)hmacSha1withKey:(NSString *)key forString:(NSString *)string;
+ (NSString *)stringWithHexBytes:(NSData *)data;

@end
