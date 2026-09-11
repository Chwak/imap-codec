use std::num::NonZeroU32;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::core::Vec1;

#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct UidSet(pub Vec1<UidElement>);

#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum UidElement {
    Single(NonZeroU32),
    Range(NonZeroU32, NonZeroU32),
}

impl UidSet {
    /// The set of these UIDs, with runs of consecutive ones written as
    /// ranges.
    ///
    /// `None` for an empty slice: RFC 4315 Section 3's `uid-set` is
    /// `1*(uniqueid / uid-range)`, so there is no such thing as an empty
    /// one, and a caller with nothing to report has no `COPYUID` or
    /// `APPENDUID` to send.
    ///
    /// The order given is kept — RFC 4315 Section 3 requires `COPYUID`'s
    /// two sets to correspond message by message, so sorting them here
    /// would break the pairing — and only *adjacent* ascending runs are
    /// folded.
    #[must_use]
    pub fn collapsed(uids: &[NonZeroU32]) -> Option<Self> {
        let mut elements: Vec<UidElement> = Vec::new();
        for uid in uids {
            match elements.last_mut() {
                Some(UidElement::Single(one)) if one.get() + 1 == uid.get() => {
                    *elements.last_mut().expect("just matched") = UidElement::Range(*one, *uid);
                }
                Some(UidElement::Range(_, end)) if end.get() + 1 == uid.get() => *end = *uid,
                _ => elements.push(UidElement::Single(*uid)),
            }
        }
        Vec1::try_from(elements).ok().map(Self)
    }
}

impl From<NonZeroU32> for UidSet {
    fn from(uid: NonZeroU32) -> Self {
        Self(Vec1::from(UidElement::Single(uid)))
    }
}
