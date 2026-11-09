//
// Copyright (C) 2026 BayLibre
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! OP-TEE TA logger — redirects Rust log to OP-TEE trace (UART output)

#![no_std]

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, Ordering};
use log::{Level, LevelFilter, Metadata, Record};

struct OpteeLogger;

static MAX_LEVEL: AtomicU8 = AtomicU8::new(LevelFilter::Trace as u8);
static LOGGER: OpteeLogger = OpteeLogger;

/// A log line on the stack, truncated when full. The last two bytes are kept
/// for the newline and the NUL terminator.
struct Line {
    data: [u8; 512],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let n = s.len().min(self.data.len() - 2 - self.len);
        self.data[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

impl OpteeLogger {
    fn max_level(&self) -> LevelFilter {
        match MAX_LEVEL.load(Ordering::Relaxed) {
            0 => LevelFilter::Off,
            1 => LevelFilter::Error,
            2 => LevelFilter::Warn,
            3 => LevelFilter::Info,
            4 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        }
    }
}

impl log::Log for OpteeLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let level_str = match record.level() {
            Level::Error => "TA_RUST_ERROR",
            Level::Warn => "TA_RUST_WARN ",
            Level::Info => "TA_RUST_INFO ",
            Level::Debug => "TA_RUST_DEBUG",
            Level::Trace => "TA_RUST_TRACE",
        };

        // Formatted on the stack: a heap allocation could fail, which aborts
        // the TA.
        let mut line = Line { data: [0; 512], len: 0 };
        let _ = write!(line, "[{}] {}", level_str, record.args());
        line.data[line.len] = b'\n';
        line.data[line.len + 1] = 0;

        // SAFETY: `line.data` is NUL-terminated.
        unsafe {
            optee_utee_sys::trace_ext_puts(line.data.as_ptr());
        }
    }

    fn flush(&self) {}
}

pub struct OpteeLoggerConfig {
    pub max_level: LevelFilter,
}

impl Default for OpteeLoggerConfig {
    fn default() -> Self {
        OpteeLoggerConfig {
            max_level: LevelFilter::Trace,
        }
    }
}

pub fn init() -> Result<(), log::SetLoggerError> {
    init_with_config(OpteeLoggerConfig::default())
}

pub fn init_with_config(config: OpteeLoggerConfig) -> Result<(), log::SetLoggerError> {
    MAX_LEVEL.store(config.max_level as u8, Ordering::Relaxed);
    log::set_logger(&LOGGER)?;
    log::set_max_level(config.max_level);
    Ok(())
}
