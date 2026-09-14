//! Object identifiers (RFC 8474): stable ids for mailboxes, messages and
//! threads, the same ones JMAP uses where a server speaks both.

use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    command::CommandBody,
    error::{ValidationError, ValidationErrorKind},
};

/// An object identifier.
///
/// ```abnf
/// objectid = 1*255(ALPHA / DIGIT / "_" / "-")
/// ```
///
/// Case matters (RFC 8474 Section 8.1).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "String"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ObjectId<'a>(Cow<'a, str>);

impl<'a> ObjectId<'a> {
    /// Whether a value is an object identifier.
    pub fn validate(value: impl AsRef<[u8]>) -> Result<(), ValidationError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(ValidationError::new(ValidationErrorKind::Empty));
        }
        if value.len() > 255 {
            return Err(ValidationError::new(ValidationErrorKind::Invalid));
        }
        if let Some(at) = value.iter().position(|b| !is_objectid_char(*b)) {
            return Err(ValidationError::new(ValidationErrorKind::InvalidByteAt {
                byte: value[at],
                at,
            }));
        }
        Ok(())
    }

    /// The identifier.
    pub fn inner(&self) -> &str {
        self.0.as_ref()
    }

    /// Constructs an identifier without validation.
    ///
    /// # Warning: IMAP conformance
    ///
    /// The caller must ensure that `inner` is valid according to
    /// [`Self::validate`]. Note: this method will `panic!` on wrong input in
    /// debug builds.
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

/// `ALPHA / DIGIT / "_" / "-"`
pub fn is_objectid_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

impl<'a> TryFrom<&'a str> for ObjectId<'a> {
    type Error = ValidationError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(Cow::Borrowed(value)))
    }
}

impl TryFrom<String> for ObjectId<'_> {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(Cow::Owned(value)))
    }
}

impl AsRef<str> for ObjectId<'_> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Display for ObjectId<'_> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(self.0.as_ref())
    }
}

// By hand rather than through `impl_arbitrary_try_from!`, so an identifier
// of any lifetime can be made — `StatusDataItem` holds a `'static` one.
#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ObjectId<'_> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        ObjectId::try_from(String::arbitrary(u)?).map_err(|_| arbitrary::Error::IncorrectFormat)
    }
}

impl CommandBody<'_> {
    /// `UNAUTHENTICATE` (RFC 8437).
    ///
    /// <div class="warning">
    /// This extension must only be used when the server advertised support for it sending the UNAUTHENTICATE capability.
    /// </div>
    pub fn unauthenticate() -> Self {
        CommandBody::Unauthenticate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_objectid_validation() {
        assert!(ObjectId::try_from("F2212ea87-6097-4256-9d51-71338625").is_ok());
        assert!(ObjectId::try_from("T_1").is_ok());
        assert!(ObjectId::try_from("").is_err());
        assert!(ObjectId::try_from("a b").is_err());
        assert!(ObjectId::try_from("a.b").is_err());
        assert!(ObjectId::try_from("a".repeat(255).as_str()).is_ok());
        assert!(ObjectId::try_from("a".repeat(256).as_str()).is_err());
    }
}
