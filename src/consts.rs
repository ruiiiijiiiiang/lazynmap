use std::fmt::Display;
use strum::IntoEnumIterator;

pub const IDLE_SCAN_TYPE_INDEX: usize = 9;
pub const FTP_SCAN_TYPE_INDEX: usize = 10;
pub const SCANFLAGS_SCAN_TYPE_INDEX: usize = 11;

pub trait IndexableEnum: Copy + Display + Eq + IntoEnumIterator + PartialEq {
    fn as_index(&self) -> usize;
    fn from_index(index: usize) -> Option<Self>;
    fn all_labels() -> Vec<String>;
}

impl<T> IndexableEnum for T
where
    T: Copy + Display + Eq + IntoEnumIterator + PartialEq,
{
    fn as_index(&self) -> usize {
        T::iter()
            .position(|variant| variant == *self)
            .unwrap_or_else(|| panic!("Variant not found in EnumIterator!"))
    }

    fn from_index(index: usize) -> Option<Self> {
        T::iter().nth(index)
    }

    fn all_labels() -> Vec<String> {
        Self::iter().map(|t| t.to_string()).collect()
    }
}
