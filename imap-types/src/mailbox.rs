//! Mailbox-related types.

use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
    str::from_utf8,
};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "arbitrary")]
use crate::arbitrary::impl_arbitrary_try_from;
use crate::{
    core::{AString, Atom, IString, Vec1, impl_try_from},
    error::{ValidationError, ValidationErrorKind},
    mailbox::error::MailboxOtherError,
    utils::indicators::is_list_char,
};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ListCharString<'a>(pub(crate) Cow<'a, str>);

impl<'a> ListCharString<'a> {
    pub fn validate(value: impl AsRef<[u8]>) -> Result<(), ValidationError> {
        let value = value.as_ref();

        if value.is_empty() {
            return Err(ValidationError::new(ValidationErrorKind::Empty));
        }

        if let Some(at) = value.iter().position(|b| !is_list_char(*b)) {
            return Err(ValidationError::new(ValidationErrorKind::InvalidByteAt {
                byte: value[at],
                at,
            }));
        };

        Ok(())
    }

    /// Constructs a list char string without validation.
    ///
    /// # Warning: IMAP conformance
    ///
    /// The caller must ensure that `inner` is valid according to [`Self::validate`]. Failing to do
    /// so may create invalid/unparsable IMAP messages, or even produce unintended protocol flows.
    /// Do not call this constructor with untrusted data.
    ///
    /// Note: This method will `panic!` on wrong input in debug builds.
    pub fn unvalidated<C>(inner: C) -> Self
    where
        C: Into<Cow<'a, str>>,
    {
        let inner = inner.into();

        #[cfg(debug_assertions)]
        Self::validate(inner.as_bytes()).unwrap();

        Self(inner)
    }
}

impl<'a> TryFrom<&'a str> for ListCharString<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::validate(value)?;

        Ok(Self(Cow::Borrowed(value)))
    }
}

impl TryFrom<String> for ListCharString<'_> {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;

        Ok(Self(Cow::Owned(value)))
    }
}

impl AsRef<[u8]> for ListCharString<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ListMailbox<'a> {
    Token(ListCharString<'a>),
    String(IString<'a>),
}

impl<'a> TryFrom<&'a str> for ListMailbox<'a> {
    type Error = ValidationError;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if s.is_empty() {
            // Safety: We know that an empty string can always be converted into a quoted string.
            return Ok(ListMailbox::String(IString::Quoted(s.try_into().unwrap())));
        }

        if let Ok(lcs) = ListCharString::try_from(s) {
            return Ok(ListMailbox::Token(lcs));
        }

        Ok(ListMailbox::String(s.try_into()?))
    }
}

impl TryFrom<String> for ListMailbox<'_> {
    type Error = ValidationError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.is_empty() {
            // Safety: We know that an empty string can always be converted into a quoted string.
            return Ok(ListMailbox::String(IString::Quoted(s.try_into().unwrap())));
        }

        // TODO(efficiency)
        if let Ok(lcs) = ListCharString::try_from(s.clone()) {
            return Ok(ListMailbox::Token(lcs));
        }

        Ok(ListMailbox::String(s.try_into()?))
    }
}

/// 5.1. Mailbox Naming
///
/// Mailbox names are 7-bit.  Client implementations MUST NOT attempt to
/// create 8-bit mailbox names, and SHOULD interpret any 8-bit mailbox
/// names returned by LIST or LSUB as UTF-8.  Server implementations
/// SHOULD prohibit the creation of 8-bit mailbox names, and SHOULD NOT
/// return 8-bit mailbox names in LIST or LSUB.  See section 5.1.3 for
/// more information on how to represent non-ASCII mailbox names.
///
/// Note: 8-bit mailbox names were undefined in earlier
/// versions of this protocol.  Some sites used a local 8-bit
/// character set to represent non-ASCII mailbox names.  Such
/// usage is not interoperable, and is now formally deprecated.
///
/// The case-insensitive mailbox name INBOX is a special name reserved to
/// mean "the primary mailbox for this user on this server".  The
/// interpretation of all other names is implementation-dependent.
///
/// In particular, this specification takes no position on case
/// sensitivity in non-INBOX mailbox names.  Some server implementations
/// are fully case-sensitive; others preserve case of a newly-created
/// name but otherwise are case-insensitive; and yet others coerce names
/// to a particular case.  Client implementations MUST interact with any
/// of these.  If a server implementation interprets non-INBOX mailbox
/// names as case-insensitive, it MUST treat names using the
/// international naming convention specially as described in section 5.1.3.
///
/// There are certain client considerations when creating a new mailbox name:
///
/// 1) Any character which is one of the atom-specials (see the Formal Syntax) will require
///    that the mailbox name be represented as a quoted string or literal.
/// 2) CTL and other non-graphic characters are difficult to represent in a user interface
///    and are best avoided.
/// 3) Although the list-wildcard characters ("%" and "*") are valid in a mailbox name, it is
///    difficult to use such mailbox names with the LIST and LSUB commands due to the conflict
///    with wildcard interpretation.
/// 4) Usually, a character (determined by the server implementation) is reserved to delimit
///    levels of hierarchy.
/// 5) Two characters, "#" and "&", have meanings by convention, and should be avoided except
///    when used in that convention.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum Mailbox<'a> {
    Inbox,
    Other(MailboxOther<'a>),
}

impl_try_from!(AString<'a>, 'a, &'a [u8], Mailbox<'a>);
impl_try_from!(AString<'a>, 'a, Vec<u8>, Mailbox<'a>);
impl_try_from!(AString<'a>, 'a, &'a str, Mailbox<'a>);
impl_try_from!(AString<'a>, 'a, String, Mailbox<'a>);

impl<'a> From<AString<'a>> for Mailbox<'a> {
    fn from(value: AString<'a>) -> Self {
        match from_utf8(value.as_ref()) {
            Ok(value) if value.eq_ignore_ascii_case("inbox") => Self::Inbox,
            _ => Self::Other(MailboxOther::try_from(value).unwrap()),
        }
    }
}

// We do not implement `AsRef<...>` for `Mailbox` because we want to enforce that a consumer
// `match`es on `Mailbox::Inbox`/`Mailbox::Other`.

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "AString<'a>"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct MailboxOther<'a>(pub(crate) AString<'a>);

impl<'a> MailboxOther<'a> {
    pub fn validate(value: impl AsRef<[u8]>) -> Result<(), MailboxOtherError> {
        if value.as_ref().eq_ignore_ascii_case(b"inbox") {
            return Err(MailboxOtherError::Reserved);
        }

        Ok(())
    }

    pub fn inner(&self) -> &AString<'_> {
        &self.0
    }

    /// Constructs a mailbox without validation.
    ///
    /// # Warning: IMAP conformance
    ///
    /// The caller must ensure that `value` is valid according to [`Self::validate`]. Failing to do
    /// so may create invalid/unparsable IMAP messages, or even produce unintended protocol flows.
    /// Do not call this constructor with untrusted data.
    ///
    /// Note: This method will `panic!` on wrong input in debug builds.
    pub fn unvalidated(value: AString<'a>) -> Self {
        #[cfg(debug_assertions)]
        Self::validate(&value).unwrap();

        Self(value)
    }
}

macro_rules! impl_try_from_mailbox_other {
    ($from:ty) => {
        impl<'a> TryFrom<$from> for MailboxOther<'a> {
            type Error = MailboxOtherError;

            fn try_from(value: $from) -> Result<Self, Self::Error> {
                let astring = AString::try_from(value)?;

                Self::validate(&astring)?;

                Ok(Self(astring))
            }
        }
    };
}

impl_try_from_mailbox_other!(&'a [u8]);
impl_try_from_mailbox_other!(Vec<u8>);
impl_try_from_mailbox_other!(&'a str);
impl_try_from_mailbox_other!(String);

impl<'a> TryFrom<AString<'a>> for MailboxOther<'a> {
    type Error = MailboxOtherError;

    fn try_from(value: AString<'a>) -> Result<Self, Self::Error> {
        Self::validate(&value)?;

        Ok(Self(value))
    }
}

impl AsRef<[u8]> for MailboxOther<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Error-related types.
pub mod error {
    use thiserror::Error;

    use crate::error::ValidationError;

    #[derive(Clone, Debug, Eq, Error, Hash, Ord, PartialEq, PartialOrd)]
    pub enum MailboxOtherError {
        #[error(transparent)]
        Literal(#[from] ValidationError),
        #[error("Reserved: Please use one of the typed variants")]
        Reserved,
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;
    #[cfg(feature = "serde")]
    use crate::core::AtomExt;
    use crate::core::{AString, IString, Literal, LiteralMode};

    #[test]
    fn test_conversion_mailbox() {
        let tests = [
            ("inbox", Mailbox::Inbox),
            ("inboX", Mailbox::Inbox),
            ("Inbox", Mailbox::Inbox),
            ("InboX", Mailbox::Inbox),
            ("INBOX", Mailbox::Inbox),
            (
                "INBO²",
                Mailbox::Other(MailboxOther(AString::String(IString::Literal(Literal {
                    data: Cow::Borrowed("INBO²".as_bytes()),
                    mode: LiteralMode::Sync,
                })))),
            ),
        ];

        for (test, expected) in tests {
            let got = Mailbox::try_from(test).unwrap();
            assert_eq!(expected, got);

            let got = Mailbox::try_from(String::from(test)).unwrap();
            assert_eq!(expected, got);
        }
    }

    #[test]
    fn test_conversion_mailbox_failing() {
        let tests = ["\x00", "A\x00", "\x00A"];

        for test in tests {
            assert!(Mailbox::try_from(test).is_err());
            assert!(Mailbox::try_from(String::from(test)).is_err());
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialization_list_char_string() {
        let valid_input = r#""OneWord""#;
        let invalid_input = r#""Two Words""#;

        let list_char_string = serde_json::from_str::<ListCharString>(valid_input)
            .expect("valid input should deserialize successfully");
        assert_eq!(list_char_string, ListCharString(Cow::Borrowed("OneWord")));

        let err = serde_json::from_str::<ListCharString>(invalid_input)
            .expect_err("invalid input should not deserialize successfully");
        assert_eq!(
            err.to_string(),
            r"Validation failed: Invalid byte b'\x20' at index 3"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_deserialization_mailbox_other() {
        let valid_input = r#"{ "type": "Atom", "content": "other" }"#;
        let invalid_input = r#"{ "type": "Atom", "content": "inbox" }"#;

        let mailbox_other = serde_json::from_str::<MailboxOther>(valid_input)
            .expect("valid input should deserialize successfully");
        assert_eq!(
            mailbox_other,
            MailboxOther(AString::Atom(AtomExt(Cow::Borrowed("other"))))
        );

        let err = serde_json::from_str::<MailboxOther>(invalid_input)
            .expect_err("invalid input should not deserialize successfully");
        assert_eq!(
            err.to_string(),
            r"Reserved: Please use one of the typed variants"
        );
    }
}

/// What a mailbox is for: RFC 6154's special-use attributes.
///
/// A client uses these two ways round. A server that advertises
/// `SPECIAL-USE` reports them as name attributes in its `LIST` responses,
/// so a client can find the mailbox sent mail belongs in without guessing
/// from its name — which is the whole point, since the name is in the
/// user's language and "Sent" is not. A server that advertises
/// `CREATE-SPECIAL-USE` also accepts them on `CREATE`, so a client
/// setting an account up can say what it is making rather than hoping the
/// server guesses.
///
/// ```abnf
/// use-attr = "\\All" / "\\Archive" / "\\Drafts" / "\\Flagged" /
///            "\\Junk" / "\\Sent" / "\\Trash" / use-attr-ext
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum MailboxUse<'a> {
    /// Every message, however it is filed (`\All`).
    All,
    /// Kept but out of the way (`\Archive`).
    Archive,
    /// Written and not sent (`\Drafts`).
    Drafts,
    /// Marked as important (`\Flagged`).
    Flagged,
    /// Spam (`\Junk`).
    Junk,
    /// Sent (`\Sent`).
    Sent,
    /// Deleted, pending removal (`\Trash`).
    Trash,
    /// `use-attr-ext`: an attribute this crate has no name for.
    Other(MailboxUseOther<'a>),
}

impl<'a> From<Atom<'a>> for MailboxUse<'a> {
    fn from(value: Atom<'a>) -> Self {
        match value.as_ref().to_ascii_lowercase().as_ref() {
            "all" => Self::All,
            "archive" => Self::Archive,
            "drafts" => Self::Drafts,
            "flagged" => Self::Flagged,
            "junk" => Self::Junk,
            "sent" => Self::Sent,
            "trash" => Self::Trash,
            _ => Self::Other(MailboxUseOther(value)),
        }
    }
}

impl Display for MailboxUse<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Self::All => f.write_str("\\All"),
            Self::Archive => f.write_str("\\Archive"),
            Self::Drafts => f.write_str("\\Drafts"),
            Self::Flagged => f.write_str("\\Flagged"),
            Self::Junk => f.write_str("\\Junk"),
            Self::Sent => f.write_str("\\Sent"),
            Self::Trash => f.write_str("\\Trash"),
            Self::Other(other) => write!(f, "\\{}", other.0),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl_arbitrary_try_from! { MailboxUse<'a>, Atom<'a> }

/// A special-use attribute this crate has no name for.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct MailboxUseOther<'a>(Atom<'a>);

impl AsRef<str> for MailboxUseOther<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

/// The mailbox patterns of a `LIST` command.
///
/// RFC 5258 Section 3 lets `LIST` take several patterns in parentheses,
/// and a mailbox that matches any of them is listed once. One pattern in
/// parentheses is not the same command as the same pattern bare: `LIST ""
/// ("")` is extended, and RFC 5258 Section 3 has the empty name mean
/// nothing special there, where `LIST "" ""` asks for the hierarchy
/// delimiter. So the two spellings are kept apart.
///
/// ```abnf
/// mbox-or-pat = list-mailbox / patterns
/// patterns    = "(" list-mailbox *(SP list-mailbox) ")"
/// ```
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ListPatterns<'a> {
    /// One pattern, not in parentheses: the `LIST` of RFC 3501.
    One(ListMailbox<'a>),
    /// Patterns in parentheses (RFC 5258 Section 3).
    Several(Vec1<ListMailbox<'a>>),
}

impl ListPatterns<'_> {
    /// The patterns, however they were written.
    pub fn as_slice(&self) -> &[ListMailbox<'_>] {
        match self {
            Self::One(one) => std::slice::from_ref(one),
            Self::Several(several) => several.as_ref(),
        }
    }
}

impl<'a> From<ListMailbox<'a>> for ListPatterns<'a> {
    fn from(one: ListMailbox<'a>) -> Self {
        Self::One(one)
    }
}

/// A `LIST` selection option (RFC 5258 Section 3.1, RFC 6154 Section 5.1).
///
/// Option names are case-insensitive (RFC 5258 Section 9.2). An option
/// this crate has no name for is not accepted: RFC 5258 Section 3 has the
/// server answer `BAD` to an option it does not recognise, and reading
/// `option-extension` here would leave the server unable to tell one it
/// knows from one it does not — the same reasoning as
/// `search-ret-opt-ext` for `SEARCH RETURN`.
///
/// ```abnf
/// list-select-base-opt        = "SUBSCRIBED" / option-extension
/// list-select-base-opt        =/ "SPECIAL-USE"   ; RFC 6154
/// list-select-independent-opt = "REMOTE" / option-extension
/// list-select-mod-opt         = "RECURSIVEMATCH" / option-extension
/// ```
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToStatic)]
pub enum ListSelectOption {
    /// Only subscribed names, including subscribed names that do not
    /// exist (a base option).
    Subscribed,
    /// Remote mailboxes too, as RFC 2193 describes them (an independent
    /// option).
    Remote,
    /// Also a name that does not match the criteria itself but has a
    /// descendant that does, with `CHILDINFO` saying why (a modifier: it
    /// needs a base option beside it).
    RecursiveMatch,
    /// Only mailboxes with a special-use attribute (RFC 6154 Section 5.1;
    /// a base option).
    SpecialUse,
}

impl ListSelectOption {
    /// Whether this is a base option, which is what a modifier such as
    /// `RECURSIVEMATCH` modifies.
    pub fn is_base(&self) -> bool {
        matches!(self, Self::Subscribed | Self::SpecialUse)
    }

    /// Whether this is an independent option, which may be the only kind
    /// in the list.
    pub fn is_independent(&self) -> bool {
        matches!(self, Self::Remote)
    }

    /// Whether a list of options is one RFC 5258 Section 6 allows: empty,
    /// holding a base option, or holding independent options only. So
    /// `(RECURSIVEMATCH)` and `(RECURSIVEMATCH REMOTE)` are not, which
    /// RFC 5258 Section 3.1 has the server refuse with `BAD`.
    pub fn valid_combination(options: &[ListSelectOption]) -> bool {
        options.iter().any(Self::is_base) || options.iter().all(Self::is_independent)
    }
}

impl AsRef<str> for ListSelectOption {
    fn as_ref(&self) -> &str {
        match self {
            Self::Subscribed => "SUBSCRIBED",
            Self::Remote => "REMOTE",
            Self::RecursiveMatch => "RECURSIVEMATCH",
            Self::SpecialUse => "SPECIAL-USE",
        }
    }
}

/// A `LIST` return option (RFC 5258 Section 3.2, RFC 5819 Section 2, RFC
/// 6154 Section 5.1). Unrecognised options are not accepted, for the
/// reason given at [`ListSelectOption`].
///
/// ```abnf
/// return-option =  "SUBSCRIBED" / "CHILDREN" / option-extension
/// return-option =/ "STATUS" SP "(" status-att *(SP status-att) ")"  ; RFC 5819
/// return-option =/ "SPECIAL-USE"                                    ; RFC 6154
/// ```
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ListReturnOption {
    /// `\Subscribed` on each name that is subscribed.
    Subscribed,
    /// `\HasChildren` or `\HasNoChildren` on each name.
    Children,
    /// A `STATUS` response for each selectable mailbox listed (LIST-STATUS).
    Status(Vec1<crate::status::StatusDataItemName>),
    /// The special-use attributes of each mailbox.
    SpecialUse,
}

/// An extended data item at the end of a `LIST` response (RFC 5258
/// Section 3.5 and Section 6).
///
/// ```abnf
/// mbox-list-extended      = "(" [mbox-list-extended-item
///                           *(SP mbox-list-extended-item)] ")"
/// childinfo-extended-item = "CHILDINFO" SP "("
///                           list-select-base-opt-quoted
///                           *(SP list-select-base-opt-quoted) ")"
/// oldname-extended-item   = "OLDNAME" SP "(" mailbox ")"
/// ```
///
/// `mbox-list-extended-item` in general is a tag and RFC 4466's
/// `tagged-ext-val`. Only the two items RFC 5258 defines are read: a
/// server sends extended items only for options the client asked for, and
/// a client that asked for no other has none to expect.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ListExtendedItem<'a> {
    /// `RECURSIVEMATCH` listed this name because a descendant meets these
    /// selection criteria.
    ChildInfo(Vec1<ListSelectOption>),
    /// The mailbox was renamed from this name (RFC 5258 Section 6, as
    /// NOTIFY and RENAME use it).
    OldName(Mailbox<'a>),
}
