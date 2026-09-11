//! Search-related types.

use std::num::NonZeroU32;
#[cfg(feature = "ext_condstore_qresync")]
use std::num::NonZeroU64;

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "ext_condstore_qresync")]
use crate::extensions::condstore_qresync::{AttributeFlag, EntryTypeReq};
use crate::{
    core::{AString, Atom, Tag, Vec1},
    datetime::NaiveDate,
    extensions::uidplus::UidSet,
    sequence::SequenceSet,
};

/// The defined search keys.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum SearchKey<'a> {
    // <Not in RFC.>
    //
    // IMAP doesn't have a dedicated AND operator in its search syntax.
    // ANDing multiple search keys works by concatenating them with an ascii space.
    // Introducing this variant makes sense, because
    //   * it may help in understanding the RFC
    //   * and it can be used to distinguish between a single search key
    //     and multiple search keys.
    //
    // See also the corresponding `search` parser.
    And(Vec1<SearchKey<'a>>),

    /// Messages with message sequence numbers corresponding to the
    /// specified message sequence number set.
    SequenceSet(SequenceSet),

    /// All messages in the mailbox; the default initial key for ANDing.
    All,

    /// Messages with the \Answered flag set.
    Answered,

    /// Messages that contain the specified string in the envelope
    /// structure's BCC field.
    Bcc(AString<'a>),

    /// Messages whose internal date (disregarding time and timezone)
    /// is earlier than the specified date.
    Before(NaiveDate),

    /// Messages that contain the specified string in the body of the
    /// message.
    Body(AString<'a>),

    /// Messages that contain the specified string in the envelope
    /// structure's CC field.
    Cc(AString<'a>),

    /// Messages with the \Deleted flag set.
    Deleted,

    /// Messages with the \Draft flag set.
    Draft,

    /// Messages with the \Flagged flag set.
    Flagged,

    /// Messages that contain the specified string in the envelope
    /// structure's FROM field.
    From(AString<'a>),

    /// Messages that have a header with the specified field-name (as
    /// defined in [RFC-2822]) and that contains the specified string
    /// in the text of the header (what comes after the colon).  If the
    /// string to search is zero-length, this matches all messages that
    /// have a header line with the specified field-name regardless of
    /// the contents.
    Header(AString<'a>, AString<'a>),

    /// Messages with the specified keyword flag set.
    Keyword(Atom<'a>),

    /// Messages with an [RFC-2822] size larger than the specified
    /// number of octets.
    Larger(u32),

    /// Messages that have the \Recent flag set but not the \Seen flag.
    /// This is functionally equivalent to "(RECENT UNSEEN)".
    New,

    /// Messages that do not match the specified search key.
    Not(Box<SearchKey<'a>>),

    /// Messages that do not have the \Recent flag set.  This is
    /// functionally equivalent to "NOT RECENT" (as opposed to "NOT
    /// NEW").
    Old,

    /// Messages whose internal date (disregarding time and timezone)
    /// is within the specified date.
    On(NaiveDate),

    /// Messages that match either search key.
    Or(Box<SearchKey<'a>>, Box<SearchKey<'a>>),

    /// Messages that have the \Recent flag set.
    Recent,

    /// Messages that have the \Seen flag set.
    Seen,

    /// Messages whose [RFC-2822] Date: header (disregarding time and
    /// timezone) is earlier than the specified date.
    SentBefore(NaiveDate),

    /// Messages whose [RFC-2822] Date: header (disregarding time and
    /// timezone) is within the specified date.
    SentOn(NaiveDate),

    /// Messages whose [RFC-2822] Date: header (disregarding time and
    /// timezone) is within or later than the specified date.
    SentSince(NaiveDate),

    /// Messages whose internal date (disregarding time and timezone)
    /// is within or later than the specified date.
    Since(NaiveDate),

    /// Messages with an [RFC-2822] size smaller than the specified
    /// number of octets.
    Smaller(u32),

    /// Messages that contain the specified string in the envelope
    /// structure's SUBJECT field.
    Subject(AString<'a>),

    /// Messages that contain the specified string in the header or
    /// body of the message.
    Text(AString<'a>),

    /// Messages that contain the specified string in the envelope
    /// structure's TO field.
    To(AString<'a>),

    /// Messages with unique identifiers corresponding to the specified
    /// unique identifier set.  Sequence set ranges are permitted.
    Uid(SequenceSet),

    /// Messages that do not have the \Answered flag set.
    Unanswered,

    /// Messages that do not have the \Deleted flag set.
    Undeleted,

    /// Messages that do not have the \Draft flag set.
    Undraft,

    /// Messages that do not have the \Flagged flag set.
    Unflagged,

    /// Messages that do not have the specified keyword flag set.
    Unkeyword(Atom<'a>),

    /// Messages that do not have the \Seen flag set.
    Unseen,

    #[cfg(feature = "ext_condstore_qresync")]
    #[cfg_attr(docsrs, doc(cfg("ext_condstore_qresync")))]
    ModSequence {
        entry: Option<(AttributeFlag<'a>, EntryTypeReq)>,
        modseq: u64,
    },
}

impl SearchKey<'_> {
    pub fn uid<S>(sequence_set: S) -> Self
    where
        S: Into<SequenceSet>,
    {
        Self::Uid(sequence_set.into())
    }
}

/// What a `SEARCH` (or `SORT`) is asked to return rather than the whole
/// list of matches.
///
/// RFC 4731 Section 3.1 added `RETURN` to `SEARCH`, and RFC 5267
/// Section 4 gave `SORT` the same option list; RFC 9051 Section 6.4.4
/// folded both into IMAP4rev2. A command with no `RETURN` at all keeps
/// the untagged `SEARCH` response of RFC 3501, which is why this is an
/// `Option<Vec<_>>` at the command and not a `Vec` that happens to be
/// empty: `SEARCH RETURN () ALL` is defined to mean `ALL` and is a
/// different command from `SEARCH ALL`.
///
/// ```abnf
/// search-return-opt = "MIN" / "MAX" / "ALL" / "COUNT" / search-ret-opt-ext
/// ```
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToStatic)]
pub enum SearchReturnOption {
    /// The lowest message number or UID that matched.
    Min,
    /// The highest message number or UID that matched.
    Max,
    /// Every match, as a sequence set.
    All,
    /// How many matched.
    Count,
    /// `PARTIAL <range>` (RFC 5267 Section 4.4): only this slice of the
    /// result, counted from one in the order the result is in.
    ///
    /// It is what lets a client show the first screenful of a search
    /// over a mailbox of a hundred thousand messages without carrying
    /// the other ninety-nine thousand across the wire.
    Partial(PartialRange),
    /// `UPDATE` (RFC 5267 Section 4.3): keep this search alive and tell
    /// me when its answer changes.
    Update,
    /// `CONTEXT` (RFC 5267 Section 4.2): remember the result, so a later
    /// `PARTIAL` asks for a slice of the same answer rather than of a
    /// search run again over a mailbox that has moved on.
    Context,
}

impl AsRef<str> for SearchReturnOption {
    fn as_ref(&self) -> &str {
        match self {
            SearchReturnOption::Min => "MIN",
            SearchReturnOption::Max => "MAX",
            SearchReturnOption::All => "ALL",
            SearchReturnOption::Count => "COUNT",
            SearchReturnOption::Partial(_) => "PARTIAL",
            SearchReturnOption::Update => "UPDATE",
            SearchReturnOption::Context => "CONTEXT",
        }
    }
}

/// A slice of a search result, counted from one (RFC 5267 Section 4.4).
///
/// ```abnf
/// partial-range = nz-number ":" nz-number
/// ```
///
/// Neither end may be `*`, and neither may be zero, which is why this is
/// its own type rather than a [`SequenceSet`]: `PARTIAL 1:*` asks for
/// "the first through the last", and a client that wanted the whole
/// result would have said `ALL`. RFC 5267 Section 4.4 makes the two ends
/// interchangeable — `4:2` is `2:4` — so the constructor orders them and
/// the encoder writes them back in order, which is also what the server
/// echoes in its answer.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToStatic)]
pub struct PartialRange {
    /// The first position wanted, from one.
    pub from: NonZeroU32,
    /// The last position wanted, inclusive.
    pub to: NonZeroU32,
}

impl PartialRange {
    /// A range with its ends in order, whichever way they were written.
    #[must_use]
    pub fn new(a: NonZeroU32, b: NonZeroU32) -> Self {
        Self {
            from: a.min(b),
            to: a.max(b),
        }
    }

    /// How many positions it covers.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.to.get() - self.from.get() + 1
    }
}

/// One datum of an `ESEARCH` response (RFC 4731 Section 3.2).
///
/// ```abnf
/// search-return-data = "MIN" SP nz-number /
///                      "MAX" SP nz-number /
///                      "ALL" SP sequence-set /
///                      "COUNT" SP number
///
/// search-return-data =/ "MODSEQ" SP mod-sequence-value    ; RFC 7162
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum SearchReturnData {
    /// `MIN`.
    Min(NonZeroU32),
    /// `MAX`.
    Max(NonZeroU32),
    /// `ALL`, never empty: a search that matched nothing omits the datum
    /// entirely (RFC 4731 Section 3.2).
    ///
    /// A [`UidSet`] and not a [`SequenceSet`], although RFC 4731 Section
    /// 3.2 writes the rule as `"ALL" SP sequence-set`, because the order
    /// is part of the answer and a `SequenceSet` does not keep one: this
    /// crate normalises one as it encodes it — which is right, since RFC
    /// 9051 Section 9's `sequence-set` is a set and `4,3,2` and `2:4`
    /// name the same messages. They do not name the same *answer* here.
    /// RFC 5267 Section 4.2 has a `SORT RETURN (ALL)` list its messages
    /// "in the order determined by the sort criteria", and a normalised
    /// set would throw away the only thing the client asked `SORT` for.
    All(UidSet),
    /// `COUNT`, which *is* sent as zero when nothing matched.
    Count(u32),
    /// `PARTIAL (<range> <results>)` (RFC 5267 Section 4.4): the slice
    /// asked for, and what was in it.
    ///
    /// The range is echoed so a client that pipelined two `PARTIAL`s can
    /// tell which slice it is holding. `None` for the results is the
    /// `NIL` RFC 5267 Section 4.4 sends for a range that begins past the
    /// end of the result — which is an answer, and not the same as a
    /// search that matched nothing.
    Partial(PartialRange, Option<UidSet>),
    /// `ADDTO (<context position> <set>)` (RFC 5267 Section 4.3.1):
    /// messages that have joined the result of a search left open with
    /// `UPDATE`.
    AddTo(u32, UidSet),
    /// `REMOVEFROM (<context position> <set>)` (RFC 5267 Section 4.3.2):
    /// messages that have left it, whether because they changed or
    /// because they were expunged.
    RemoveFrom(u32, UidSet),
    /// `MODSEQ`: the highest mod-sequence of the messages this response
    /// names (RFC 7162 Section 3.1.5). A `SEARCH` that carried a `MODSEQ`
    /// search key, or that ran with `CONDSTORE` enabled, owes the client
    /// this so it knows what its answer is current as of.
    #[cfg(feature = "ext_condstore_qresync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "ext_condstore_qresync")))]
    ModSeq(NonZeroU64),
}

/// The `ESEARCH` response (RFC 4731 Section 3.2).
///
/// The correlator is what makes this answerable out of order: a client
/// that pipelined three searches tells them apart by the tag, which the
/// untagged `SEARCH` response of RFC 3501 has nowhere to carry.
///
/// ```abnf
/// esearch-response  = "ESEARCH" [search-correlator] [SP "UID"]
///                     *(SP search-return-data)
/// search-correlator = SP "(" "TAG" SP tag-string ")"
/// ```
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct EsearchResponse<'a> {
    /// The tag of the command this answers.
    pub correlator: Option<Tag<'a>>,
    /// The numbers are UIDs rather than message sequence numbers.
    pub uid: bool,
    /// What was asked for, in the order to send it.
    pub items: Vec<SearchReturnData>,
}
