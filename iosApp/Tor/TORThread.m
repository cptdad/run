//
//  TORThread.m
//  Tor
//
//  Created by Conrad Kramer on 7/19/15.
//

#import <feature/api/tor_api.h>

#import "TORThread.h"
#import "TORLogging.h"
#import "TORConfiguration.h"

NS_ASSUME_NONNULL_BEGIN

static __weak TORThread *_thread = nil;

@interface TORThread ()

@property (nonatomic, readonly, copy, nullable) NSArray<NSString *> *arguments;

@end

@implementation TORThread

+ (nullable TORThread *)activeThread {
    return _thread;
}

- (instancetype)init {
    return [self initWithArguments:nil];
}

- (instancetype)initWithConfiguration:(nullable TORConfiguration *)configuration {
    return [self initWithArguments:[configuration compile]];
}

- (instancetype)initWithArguments:(nullable NSArray<NSString *> *)arguments {
    NSAssert(_thread == nil, @"There can only be one TORThread per process");
    self = [super init];
    if (!self)
        return nil;
    
    _thread = self;
    _arguments = [arguments copy];
    
    self.name = @"Tor";
    
    return self;
}

- (void)main {
    NSArray *arguments = self.arguments;
    int argc = (int)(arguments.count + 1);
    // NOTE (vendored-source fix): upstream iCepa declares `char *argv[argc]`
    // then writes `argv[argc] = NULL` — one element PAST the end of the array,
    // a stack buffer overflow. Under Xcode 26 / clang that stray write
    // corrupts adjacent stack state and Tor SIGSEGVs deep in option parsing
    // (base16_decode <- parse_dir_authority_line). C's argv convention needs
    // argc+1 slots so argv[argc] is a valid NULL terminator.
    char *argv[argc + 1];
    argv[0] = "tor";
    for (NSUInteger idx = 0; idx < arguments.count; idx++)
        argv[idx + 1] = (char *)[arguments[idx] UTF8String];
    argv[argc] = NULL;

//#if DEBUG
//    event_enable_debug_mode();
//#endif

    tor_main_configuration_t *cfg = tor_main_configuration_new();
    tor_main_configuration_set_command_line(cfg, argc, argv);
    tor_run_main(cfg);
    tor_main_configuration_free(cfg);
}

@end

NS_ASSUME_NONNULL_END
