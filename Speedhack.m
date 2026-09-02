#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <sys/time.h>
#import <CoreFoundation/CoreFoundation.h>
#import <objc/runtime.h>
#import <mach/mach_time.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <sys/types.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <os/lock.h>

#ifndef LC_SEGMENT_ARCH_DEPENDENT
#ifdef __LP64__
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif
#endif

// ==========================================
// 1. EMBEDDED FISHHOOK
// ==========================================
#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct load_command load_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct load_command load_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif

struct rebinding {
  const char *name;
  void *replacement;
  void **replaced;
};

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head = NULL;

static int perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                          section_t *section,
                                          intptr_t slide,
                                          nlist_t *symtab,
                                          char *strtab,
                                          uint32_t *indirect_symtab) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
  for (uint32_t i = 0; i < section->size / sizeof(void *); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_has_leading_underscore = symbol_name[0] == '_';
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint32_t j = 0; j < cur->rebindings_nel; j++) {
        uint32_t symbol_name_offset = symbol_has_leading_underscore ? 1 : 0;
        if (strcmp(&symbol_name[symbol_name_offset], cur->rebindings[j].name) == 0) {
          if (cur->rebindings[j].replaced != NULL &&
              indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
            *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
          }
          indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
          goto symbol_loop;
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
  return 0;
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  Dl_info info;
  if (dladdr(header, &info) == 0) return;

  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;

  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment) return;

  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint32_t i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
        continue;
      }
      for (uint32_t j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
            (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
        }
      }
    }
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

static int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  struct rebindings_entry *new_entry = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
  if (!new_entry) return -1;
  new_entry->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * rebindings_nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * rebindings_nel);
  new_entry->rebindings_nel = rebindings_nel;
  new_entry->next = _rebindings_head;
  _rebindings_head = new_entry;
  
  if (!_rebindings_head->next) {
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  } else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
      rebind_symbols_for_image(new_entry, _dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return 0;
}

// ==========================================
// 2. SPEED ENGINE (DYNAMIC SPEED FACTOR)
// ==========================================
static float speed_factor = 1.0f; // Tốc độ mặc định là 1.0x
static os_unfair_lock speed_lock = OS_UNFAIR_LOCK_INIT;

static int (*orig_gettimeofday)(struct timeval *tv, struct timezone *tz);
static CFAbsoluteTime (*orig_CFAbsoluteTimeGetCurrent)(void);
static uint64_t (*orig_mach_absolute_time)(void);

static struct timeval last_real_tv = {0, 0}, fake_tv = {0, 0};
static CFAbsoluteTime last_real_cf = 0, fake_cf = 0;
static uint64_t last_real_mach = 0, fake_mach = 0;

static void set_dynamic_speed(float factor) {
    os_unfair_lock_lock(&speed_lock);
    speed_factor = factor;
    if (factor == 1.0f) {
        last_real_tv = (struct timeval){0, 0};
        fake_tv = (struct timeval){0, 0};
        last_real_cf = 0;
        fake_cf = 0;
        last_real_mach = 0;
        fake_mach = 0;
    }
    os_unfair_lock_unlock(&speed_lock);
}

int my_gettimeofday(struct timeval *tv, struct timezone *tz) {
    int ret = orig_gettimeofday(tv, tz);
    if (ret != 0 || !tv) return ret;

    os_unfair_lock_lock(&speed_lock);
    if (speed_factor == 1.0f) {
        os_unfair_lock_unlock(&speed_lock);
        return ret;
    }

    if (last_real_tv.tv_sec == 0) {
        last_real_tv = *tv;
        fake_tv = *tv;
    } else {
        double delta = (tv->tv_sec - last_real_tv.tv_sec) + (tv->tv_usec - last_real_tv.tv_usec) / 1e6;
        double fake_delta = delta * speed_factor;
        long sec_add = (long)fake_delta;
        long usec_add = (long)((fake_delta - sec_add) * 1e6);

        fake_tv.tv_sec += sec_add;
        fake_tv.tv_usec += usec_add;
        if (fake_tv.tv_usec >= 1000000) {
            fake_tv.tv_sec += 1;
            fake_tv.tv_usec -= 1000000;
        }
        last_real_tv = *tv;
    }
    *tv = fake_tv;
    os_unfair_lock_unlock(&speed_lock);
    return ret;
}

CFAbsoluteTime my_CFAbsoluteTimeGetCurrent(void) {
    CFAbsoluteTime real_now = orig_CFAbsoluteTimeGetCurrent();

    os_unfair_lock_lock(&speed_lock);
    if (speed_factor == 1.0f) {
        os_unfair_lock_unlock(&speed_lock);
        return real_now;
    }

    if (last_real_cf == 0) {
        last_real_cf = real_now;
        fake_cf = real_now;
    } else {
        fake_cf += (real_now - last_real_cf) * speed_factor;
        last_real_cf = real_now;
    }
    CFAbsoluteTime result = fake_cf;
    os_unfair_lock_unlock(&speed_lock);
    return result;
}

uint64_t my_mach_absolute_time(void) {
    uint64_t real_now = orig_mach_absolute_time();

    os_unfair_lock_lock(&speed_lock);
    if (speed_factor == 1.0f) {
        os_unfair_lock_unlock(&speed_lock);
        return real_now;
    }

    if (last_real_mach == 0) {
        last_real_mach = real_now;
        fake_mach = real_now;
    } else {
        fake_mach += (uint64_t)((real_now - last_real_mach) * speed_factor);
        last_real_mach = real_now;
    }
    uint64_t result = fake_mach;
    os_unfair_lock_unlock(&speed_lock);
    return result;
}

static void swizzle_NSDate_methods(void) {
    Class nsdateClass = [NSDate class];
    Method origRef = class_getClassMethod(nsdateClass, @selector(timeIntervalSinceReferenceDate));
    if (origRef) method_setImplementation(origRef, (IMP)my_CFAbsoluteTimeGetCurrent);
    
    Method origDate = class_getClassMethod(nsdateClass, @selector(date));
    if (origDate) {
        method_setImplementation(origDate, imp_implementationWithBlock(^id(id self) {
            return [NSDate dateWithTimeIntervalSinceReferenceDate:my_CFAbsoluteTimeGetCurrent()];
        }));
    }
}

// ==========================================
// 3. TARGET-LOCKING COUNTDOWN ENGINE
// ==========================================
@interface SmartCountdownWatcher : NSObject
@property (nonatomic, strong) dispatch_source_t monitorTimer;
@property (nonatomic, weak) UIView *lockedCountdownView;
@property (nonatomic, assign) NSInteger lastSeenSecond;
@property (nonatomic, assign) BOOL isBurstActive;
@property (nonatomic, assign) BOOL isCooldown;

+ (instancetype)shared;
- (void)startWatcher;
@end

@implementation SmartCountdownWatcher

+ (instancetype)shared {
    static SmartCountdownWatcher *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        inst = [[SmartCountdownWatcher alloc] init];
        inst.lockedCountdownView = nil;
        inst.lastSeenSecond = -1;
        inst.isBurstActive = NO;
        inst.isCooldown = NO;
    });
    return inst;
}

+ (UIWindow *)getKeyWindow {
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive && [scene isKindOfClass:[UIWindowScene class]]) {
            for (UIWindow *window in ((UIWindowScene *)scene).windows) {
                if (window.isKeyWindow) return window;
            }
        }
    }
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        if (w.isKeyWindow) return w;
    }
    return [UIApplication sharedApplication].windows.firstObject;
}

// Trích xuất số nguyên từ chuỗi (hỗ trợ các dạng: "7", "07", "7s", "7 s")
- (NSInteger)parseSecondFromString:(NSString *)rawText {
    if (!rawText || rawText.length == 0 || rawText.length > 5) return -1;
    NSString *clean = [[rawText stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] lowercaseString];

    clean = [clean stringByReplacingOccurrencesOfString:@"s" withString:@""];
    clean = [clean stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

    NSScanner *scanner = [NSScanner scannerWithString:clean];
    NSInteger val = -1;
    if ([scanner scanInteger:&val] && [scanner isAtEnd]) {
        if (val >= 1 && val <= 7) return val;
    }
    return -1;
}

- (NSString *)extractTextFromView:(UIView *)view {
    if (!view) return nil;
    if ([view respondsToSelector:@selector(text)]) {
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        NSString *txt = [view performSelector:@selector(text)];
        #pragma clang diagnostic pop
        if (txt.length > 0) return txt;
    }
    if (view.accessibilityLabel.length > 0) return view.accessibilityLabel;
    if (view.accessibilityValue.length > 0) return view.accessibilityValue;
    return nil;
}

// Pha 1: Quét nhẹ tìm đúng View đang đếm lùi trong khoảng 7 -> 4
- (UIView *)findCountdownViewInHierarchy:(UIView *)view {
    if (!view || view.isHidden || view.alpha < 0.01) return nil;

    NSString *content = [self extractTextFromView:view];
    NSInteger sec = [self parseSecondFromString:content];
    if (sec >= 4 && sec <= 7) {
        return view;
    }

    for (UIView *sub in view.subviews) {
        UIView *matched = [self findCountdownViewInHierarchy:sub];
        if (matched) return matched;
    }
    return nil;
}

// Pha 2: Kích hoạt tăng tốc đúng giây thứ 3 và tự tắt sau 2 giây
- (void)triggerSpeedBurst {
    if (self.isBurstActive || self.isCooldown) return;

    self.isBurstActive = YES;
    self.isCooldown = YES;

    // BẬT tốc độ x5.0 tại giây thứ 3
    set_dynamic_speed(5.0f);

    // TẮT (trả về 1.0x chuẩn gốc) sau đúng 2.0 giây
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        set_dynamic_speed(1.0f);
        self.isBurstActive = NO;
        self.lockedCountdownView = nil; // Hủy khóa view cũ
        self.lastSeenSecond = -1;
    });

    // Cooldown 5.0 giây chống kích hoạt lặp
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        self.isCooldown = NO;
    });
}

// Luồng kiểm tra thông minh
- (void)tickCheck {
    if (self.isBurstActive || self.isCooldown) return;

    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.isBurstActive || self.isCooldown) return;

        // FAST-PATH: Nếu đã khóa được View, chỉ đọc thẳng View này (Độ phức tạp O(1))
        if (self.lockedCountdownView) {
            if (self.lockedCountdownView.isHidden || !self.lockedCountdownView.superview) {
                self.lockedCountdownView = nil;
                self.lastSeenSecond = -1;
                return;
            }

            NSString *txt = [self extractTextFromView:self.lockedCountdownView];
            NSInteger currentSec = [self parseSecondFromString:txt];

            if (currentSec == 3) {
                [self triggerSpeedBurst];
            } else if (currentSec > 0) {
                self.lastSeenSecond = currentSec;
            } else {
                // View đã đổi nội dung hoặc không còn là số đếm -> Mở khóa
                self.lockedCountdownView = nil;
                self.lastSeenSecond = -1;
            }
            return;
        }

        // SLOW-PATH: Quét nhẹ tìm View chứa đếm ngược khi chưa khóa
        UIWindow *win = [SmartCountdownWatcher getKeyWindow];
        if (!win) return;

        UIView *found = [self findCountdownViewInHierarchy:win];
        if (found) {
            NSString *txt = [self extractTextFromView:found];
            NSInteger sec = [self parseSecondFromString:txt];

            if (sec == 3) {
                // Trường hợp nổ đơn chạm thẳng số 3
                self.lockedCountdownView = found;
                [self triggerSpeedBurst];
            } else if (sec > 3) {
                // Đã bắt được nhịp đếm từ 7, 6, 5, 4 -> Khóa mục tiêu
                self.lockedCountdownView = found;
                self.lastSeenSecond = sec;
            }
        }
    });
}

- (void)startWatcher {
    dispatch_queue_t queue = dispatch_queue_create("com.speedhack.smartwatcher", DISPATCH_QUEUE_SERIAL);
    self.monitorTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);

    // Quét mỗi 80ms (đảm bảo không trễ khung hình số 3)
    dispatch_source_set_timer(self.monitorTimer,
                              dispatch_time(DISPATCH_TIME_NOW, 0),
                              (uint64_t)(0.08 * NSEC_PER_SEC),
                              (uint64_t)(0.01 * NSEC_PER_SEC));

    __weak typeof(self) weakSelf = self;
    dispatch_source_set_event_handler(self.monitorTimer, ^{
        [weakSelf tickCheck];
    });

    dispatch_resume(self.monitorTimer);
}

@end

// ==========================================
// 4. INITIALIZER
// ==========================================
__attribute__((constructor))
static void initialize_smart_speedhack(void) {
    struct rebinding rebindings[] = {
        {"gettimeofday", (void *)my_gettimeofday, (void **)&orig_gettimeofday},
        {"CFAbsoluteTimeGetCurrent", (void *)my_CFAbsoluteTimeGetCurrent, (void **)&orig_CFAbsoluteTimeGetCurrent},
        {"mach_absolute_time", (void *)my_mach_absolute_time, (void **)&orig_mach_absolute_time}
    };
    rebind_symbols(rebindings, 3);
    swizzle_NSDate_methods();

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[SmartCountdownWatcher shared] startWatcher];
    });
}
