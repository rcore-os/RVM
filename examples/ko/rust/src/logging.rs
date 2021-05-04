use {
    core::fmt,
    log::{self, Level, LevelFilter, Log, Metadata, Record},
};

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ({
        $crate::logging::print(format_args!($($arg)*));
    });
}

#[macro_export]
macro_rules! println {
    ($fmt:expr) => (print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!($fmt, "\n"), $($arg)*));
}

#[no_mangle]
extern "C" fn rvm_init_logger() {
    static LOGGER: SimpleLogger = SimpleLogger;
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(LevelFilter::Info);
    info!("[RVM] rvm_init_logger OK");
}

pub fn print(args: fmt::Arguments) {
    let s = format!("{}\0", args);
    unsafe { crate::ffi::printk(s.as_ptr() as _) };
}

struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        print(format_args!(
            "\x01{}{}\n",
            level_to_printk_code(record.level()),
            record.args()
        ));
    }
    fn flush(&self) {}
}

fn level_to_printk_code(level: Level) -> u8 {
    match level {
        Level::Error => 3, // KERN_ERR
        Level::Warn => 4,  // KERN_WARNING
        Level::Info => 6,  // KERN_INFO
        Level::Debug => 7, // KERN_DEBUG
        Level::Trace => 7, // KERN_DEBUG
    }
}
