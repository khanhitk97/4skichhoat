#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/time.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <mach/mach_time.h>
#import "fishhook.h"

// ==========================================
// 1. DYNAMIC SPEED CONTROL & HOOKS
// ==========================================
static float speed_factor = 1.0f; // Mặc định tốc độ bình thường x1

static int (*orig_gettimeofday)(struct timeval *tv, struct timezone *tz);
static CFAbsoluteTime (*orig_CFAbsoluteTimeGetCurrent)(void);
static uint64_t (*orig_mach_absolute_time)(void);

static struct timeval last_real_tv;
static struct timeval fake_tv;
static CFAbsoluteTime last_real_cf = 0;
static CFAbsoluteTime fake_cf = 0;
static uint64_t last_real_mach = 0;
static uint64_t fake_mach = 0;

int my_gettimeofday(struct timeval *tv, struct timezone *tz) {
    int ret = orig_gettimeofday(tv, tz);
    if (ret != 0 || tv == NULL) return ret;

    if (last_real_tv.tv_sec == 0) {
        last_real_tv = *tv;
        fake_tv = *tv;
    } else {
        double delta = (tv->tv_sec - last_real_tv.tv_sec) + 
                       (tv->tv_usec - last_real_tv.tv_usec) / 1000000.0;
        double fake_delta = delta * speed_factor;
        
        long sec_add = (long)fake_delta;
        long usec_add = (long)((fake_delta - sec_add) * 1000000.0);
        
        fake_tv.tv_sec += sec_add;
        fake_tv.tv_usec += usec_add;
        if (fake_tv.tv_usec >= 1000000) {
            fake_tv.tv_sec += 1;
            fake_tv.tv_usec -= 1000000;
        }
        last_real_tv = *tv;
    }

    *tv = fake_tv;
    return ret;
}

CFAbsoluteTime my_CFAbsoluteTimeGetCurrent(void) {
    CFAbsoluteTime real_now = orig_CFAbsoluteTimeGetCurrent();
    if (last_real_cf == 0) {
        last_real_cf = real_now;
        fake_cf = real_now;
    } else {
        double delta = real_now - last_real_cf;
        fake_cf += delta * speed_factor;
        last_real_cf = real_now;
    }
    return fake_cf;
}

uint64_t my_mach_absolute_time(void) {
    uint64_t real_now = orig_mach_absolute_time();
    if (last_real_mach == 0) {
        last_real_mach = real_now;
        fake_mach = real_now;
    } else {
        uint64_t delta = real_now - last_real_mach;
        fake_mach += (uint64_t)(delta * speed_factor);
        last_real_mach = real_now;
    }
    return fake_mach;
}

// ==========================================
// 2. SWIZZLE NSDATE
// ==========================================
static void swizzle_NSDate_methods(void) {
    Class nsdateClass = [NSDate class];
    
    Method origRefMethod = class_getClassMethod(nsdateClass, @selector(timeIntervalSinceReferenceDate));
    if (origRefMethod) {
        method_setImplementation(origRefMethod, (IMP)my_CFAbsoluteTimeGetCurrent);
    }
    
    Method origDateMethod = class_getClassMethod(nsdateClass, @selector(date));
    if (origDateMethod) {
        IMP newDateImp = imp_implementationWithBlock(^id(id self) {
            return [NSDate dateWithTimeIntervalSinceReferenceDate:my_CFAbsoluteTimeGetCurrent()];
        });
        method_setImplementation(origDateMethod, newDateImp);
    }
}

// ==========================================
// 3. AUTO TRIGGER THEO MÀN HÌNH ĐƠN HÀNG
// ==========================================
static BOOL is_order_screen_active = NO;

static BOOL findOrderTextInView(UIView *view) {
    if ([view isKindOfClass:[UILabel class]]) {
        NSString *text = [(UILabel *)view text];
        if ([text containsString:@"Vuốt để nhận đơn"] || [text containsString:@"Tài xế vui lòng"]) {
            return YES;
        }
    }
    for (UIView *sub in view.subviews) {
        if (findOrderTextInView(sub)) return YES;
    }
    return NO;
}

static void checkOrderScreen(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWindow = nil;
        for (UIWindow *w in [UIApplication sharedApplication].windows) {
            if (w.isKeyWindow) {
                keyWindow = w;
                break;
            }
        }
        if (!keyWindow && [UIApplication sharedApplication].windows.count > 0) {
            keyWindow = [UIApplication sharedApplication].windows.firstObject;
        }

        BOOL found = findOrderTextInView(keyWindow);
        if (found && !is_order_screen_active) {
            is_order_screen_active = YES;
            // Đợi 3 giây thực (giây thứ 4 của timer 7s) rồi tăng tốc x5
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                if (is_order_screen_active) {
                    speed_factor = 5.0f;
                }
            });
        } else if (!found && is_order_screen_active) {
            is_order_screen_active = NO;
            speed_factor = 1.0f;
        }
    });
}

// ==========================================
// 4. INITIALIZER
// ==========================================
__attribute__((constructor))
static void initialize(void) {
    struct rebinding rebindings[] = {
        {"gettimeofday", (void *)my_gettimeofday, (void **)&orig_gettimeofday},
        {"CFAbsoluteTimeGetCurrent", (void *)my_CFAbsoluteTimeGetCurrent, (void **)&orig_CFAbsoluteTimeGetCurrent},
        {"mach_absolute_time", (void *)my_mach_absolute_time, (void **)&orig_mach_absolute_time}
    };
    rebind_symbols(rebindings, 3);
    swizzle_NSDate_methods();

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        while (1) {
            checkOrderScreen();
            [NSThread sleepForTimeInterval:0.5];
        }
    });
}
