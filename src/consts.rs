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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::model::TimingTemplate;

    #[test]
    fn test_indexable_enum_as_index() {
        assert_eq!(TimingTemplate::Paranoid.as_index(), 0);
        assert_eq!(TimingTemplate::Sneaky.as_index(), 1);
        assert_eq!(TimingTemplate::Polite.as_index(), 2);
        assert_eq!(TimingTemplate::Normal.as_index(), 3);
        assert_eq!(TimingTemplate::Aggressive.as_index(), 4);
        assert_eq!(TimingTemplate::Insane.as_index(), 5);
    }

    #[test]
    fn test_indexable_enum_from_index() {
        assert_eq!(
            TimingTemplate::from_index(0),
            Some(TimingTemplate::Paranoid)
        );
        assert_eq!(TimingTemplate::from_index(1), Some(TimingTemplate::Sneaky));
        assert_eq!(TimingTemplate::from_index(2), Some(TimingTemplate::Polite));
        assert_eq!(TimingTemplate::from_index(3), Some(TimingTemplate::Normal));
        assert_eq!(
            TimingTemplate::from_index(4),
            Some(TimingTemplate::Aggressive)
        );
        assert_eq!(TimingTemplate::from_index(5), Some(TimingTemplate::Insane));
        assert_eq!(TimingTemplate::from_index(99), None);
    }

    #[test]
    fn test_indexable_enum_round_trip() {
        for i in 0..6 {
            if let Some(template) = TimingTemplate::from_index(i) {
                assert_eq!(template.as_index(), i);
            }
        }
    }

    #[test]
    fn test_indexable_enum_all_labels() {
        let labels = TimingTemplate::all_labels();
        assert_eq!(labels.len(), 6);
        assert_eq!(labels[0], "Paranoid");
        assert_eq!(labels[3], "Normal");
        assert_eq!(labels[5], "Insane");
    }
}
