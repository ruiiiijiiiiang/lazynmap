use ratatui::layout::{Position, Rect};

use crate::scan::flags::NmapFlag;

/// Number of rows the main area scrolls per mouse wheel notch.
pub const SCROLL_STEP: u16 = 3;

/// What a mouse click on a region of the screen acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClickTarget {
    /// An entry of the sections list: focuses the section and scrolls it into view.
    Section(usize),
    /// The frame of a section in the main area: focuses the section without scrolling.
    SectionBlock(usize),
    /// The checkbox of a flag: same as pressing space on it.
    Toggle(NmapFlag),
    /// The text input of a flag: same as pressing enter on it.
    Edit(NmapFlag),
    /// An option of a radio group flag: focuses and selects it.
    Radio(NmapFlag, usize),
}

/// Screen regions that react to mouse clicks, collected while the frame is drawn.
///
/// Regions registered later are drawn on top of earlier ones, so hit testing walks the list
/// backwards and the topmost region wins.
#[derive(Default)]
pub struct ClickRegions {
    regions: Vec<(Rect, ClickTarget)>,
}

impl ClickRegions {
    pub fn clear(&mut self) {
        self.regions.clear();
    }

    pub fn push(&mut self, area: Rect, target: ClickTarget) {
        if !area.is_empty() {
            self.regions.push((area, target));
        }
    }

    pub fn target_at(&self, column: u16, row: u16) -> Option<ClickTarget> {
        let position = Position::new(column, row);
        self.regions
            .iter()
            .rev()
            .find(|(area, _)| area.contains(position))
            .map(|&(_, target)| target)
    }

    pub fn area_of(&self, target: ClickTarget) -> Option<Rect> {
        self.regions
            .iter()
            .rev()
            .find(|&&(_, t)| t == target)
            .map(|&(area, _)| area)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topmost_region_wins() {
        let mut regions = ClickRegions::default();
        regions.push(Rect::new(0, 0, 10, 10), ClickTarget::SectionBlock(0));
        regions.push(Rect::new(2, 2, 3, 1), ClickTarget::Toggle(NmapFlag::Unique));

        assert_eq!(
            regions.target_at(3, 2),
            Some(ClickTarget::Toggle(NmapFlag::Unique))
        );
        assert_eq!(regions.target_at(0, 0), Some(ClickTarget::SectionBlock(0)));
        assert_eq!(regions.target_at(10, 10), None);
    }

    #[test]
    fn test_empty_regions_are_ignored() {
        let mut regions = ClickRegions::default();
        regions.push(Rect::new(0, 0, 0, 5), ClickTarget::Section(1));
        assert_eq!(regions.target_at(0, 0), None);
    }
}
