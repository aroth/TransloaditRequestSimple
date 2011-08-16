//
//  TransloaditRequest.m
// aroth
#import <CommonCrypto/CommonHMAC.h>
#import "TransloaditRequest.h"
#import "JSON.h"

@implementation TransloaditRequest

@synthesize params;

#pragma mark Init

- (id)initWithCredentials:(NSString *)key secret:(NSString *)secretKey {
	NSURL *serviceUrl = [NSURL URLWithString:@"http://api2.transloadit.com/assemblies?pretty=true"];
	[super initWithURL:serviceUrl];
    
	params = [[NSMutableDictionary alloc] init];
	secret = secretKey;
    
	NSMutableDictionary *auth = [[NSMutableDictionary alloc] init];
	[auth setObject:key forKey:@"key"];
	[params setObject:auth forKey:@"auth"];
	[auth release];
    
	return self;
}	


#pragma mark Subclassed Methods

- (void)signRequest {
	NSDateFormatter *format = [[NSDateFormatter alloc] init];
	[format setDateFormat:@"yyyy-MM-dd HH:mm-ss 'GMT'"];
	NSDate *localExpires = [[NSDate alloc] initWithTimeIntervalSinceNow:60*60];
	NSTimeInterval timeZoneOffset = [[NSTimeZone defaultTimeZone] secondsFromGMT];
	NSTimeInterval gmtTimeInterval = [localExpires timeIntervalSinceReferenceDate] - timeZoneOffset;
	NSDate *gmtExpires = [NSDate dateWithTimeIntervalSinceReferenceDate:gmtTimeInterval];
    
	[[params objectForKey:@"auth"] setObject:[format stringFromDate:gmtExpires] forKey:@"expires"];
    
	[localExpires release];
	[format release];
    
	NSString *paramsField = [params JSONRepresentation];
	NSString *signatureField = [TransloaditRequest stringWithHexBytes:[TransloaditRequest hmacSha1withKey:secret forString:paramsField]];
    
	[self setPostValue:paramsField forKey:@"params"];
	[self setPostValue:signatureField forKey:@"signature"];
}

#pragma mark Private Methods

// from: http://stackoverflow.com/questions/476455/is-there-a-library-for-iphone-to-work-with-hmac-sha-1-encoding
+ (NSData *)hmacSha1withKey:(NSString *)key forString:(NSString *)string {
	NSData *clearTextData = [string dataUsingEncoding:NSUTF8StringEncoding];
	NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
	
	uint8_t digest[CC_SHA1_DIGEST_LENGTH] = {0};
	
	CCHmacContext hmacContext;
	CCHmacInit(&hmacContext, kCCHmacAlgSHA1, keyData.bytes, keyData.length);
	CCHmacUpdate(&hmacContext, clearTextData.bytes, clearTextData.length);
	CCHmacFinal(&hmacContext, digest);
	
	return [NSData dataWithBytes:digest length:CC_SHA1_DIGEST_LENGTH];
}

// from: http://notes.stripsapp.com/nsdata-to-nsstring-as-hex-bytes/
+ (NSString *)stringWithHexBytes:(NSData *)data {
	static const char hexdigits[] = "0123456789abcdef";
	const size_t numBytes = [data length];
	const unsigned char* bytes = [data bytes];
	char *strbuf = (char *)malloc(numBytes * 2 + 1);
	char *hex = strbuf;
	NSString *hexBytes = nil;
	
	for (int i = 0; i<numBytes; ++i) {
		const unsigned char c = *bytes++;
		*hex++ = hexdigits[(c >> 4) & 0xF];
		*hex++ = hexdigits[(c ) & 0xF];
	}
	*hex = 0;
	hexBytes = [NSString stringWithUTF8String:strbuf];
	free(strbuf);
	return hexBytes;
}

#pragma mark Memory Management

- (void)dealloc
{
    [params release];
    [secret release];
	[super dealloc];
}

@end
