// os_log_with_type is a compiler-supported public macro, not a variadic FFI
// function. Let the Apple SDK encode its arguments instead of reproducing the
// private _os_log_impl buffer ABI in Rust.
#include <os/log.h>
#include <pthread.h>
#include <stddef.h>

static pthread_once_t journal_log_once = PTHREAD_ONCE_INIT;
static os_log_t journal_log;

static void initialize_journal_log(void) {
    // One bounded handle lives for the process lifetime. macOS observes logging
    // preference changes through this same object; concurrent sends share it.
    journal_log = os_log_create("org.storage-ballast-helper.sbh", "notifications");
}

int sbh_unified_log_message(unsigned char severity, const char *message) {
    os_log_type_t type;
    switch (severity) {
    case 0:
        type = OS_LOG_TYPE_INFO;
        break;
    case 2:
        type = OS_LOG_TYPE_ERROR;
        break;
    default:
        type = OS_LOG_TYPE_DEFAULT;
        break;
    }

    if (pthread_once(&journal_log_once, initialize_journal_log) != 0 ||
        journal_log == NULL) {
        return -1;
    }

    // The message is the same operator-facing summary retained on stderr.
    // Keep it visible in log show; data is never used as the format string.
    os_log_with_type(journal_log, type, "%{public}s", message);
    return 0;
}
