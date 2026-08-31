/// Return whether colored output should be disabled for this invocation.
///
/// The caller supplies the flag, environment, and terminal state so the
/// decision can be unit-tested without depending on the test process stdout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Default)]
pub enum ColorMode {
    /// Use color only when stdout is a terminal and NO_COLOR is not set.
    #[default]
    Auto,
    /// Use color even when stdout is piped or redirected.
    Always,
    /// Never use color.
    Never,
}

pub fn should_disable_color(
    no_color_flag: bool,
    color_mode: ColorMode,
    no_color_env_present: bool,
    stdout_is_terminal: bool,
) -> bool {
    if no_color_flag {
        return true;
    }

    match color_mode {
        ColorMode::Always => false,
        ColorMode::Never => true,
        ColorMode::Auto => no_color_env_present || !stdout_is_terminal,
    }
}
