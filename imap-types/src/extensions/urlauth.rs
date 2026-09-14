//! URLAUTH (RFC 4467) and its BINARY extension to URLFETCH (RFC 5524).
//!
//! A client asks the server to sign an IMAP URL (`GENURLAUTH`) so that
//! another party — most often its submission server, by `BURL` — can
//! fetch what it names (`URLFETCH`) without the client's credentials.
//! `RESETKEY` revokes what was signed.

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    body::BodyStructure,
    core::{AString, Atom, NString, NString8},
};

/// One URL a `URLFETCH` names, with what RFC 5524 asks be returned for it.
///
/// ```abnf
/// url-fetch-arg    = url-fetch-simple / url-fetch-ext
/// url-fetch-simple = url-full
/// url-fetch-ext    = "(" url-full *(SP url-fetch-param) ")"
/// url-fetch-param  = "BODY" / "BINARY" / "BODYPARTSTRUCTURE" / atom
/// ```
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct UrlFetchArg<'a> {
    /// The authorized URL.
    pub url: AString<'a>,
    /// `None` for a bare URL (RFC 4467); the parameters, which may be
    /// none, for one in parentheses (RFC 5524).
    pub params: Option<Vec<Atom<'a>>>,
}

/// What a `URLFETCH` response carries for one URL.
///
/// ```abnf
/// urldata-simple = url-full SP nstring
/// urldata-error  = url-full SP nil
/// urldata-ext    = url-full url-metadata
/// ```
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct UrlFetchData<'a> {
    /// The URL, as the client sent it.
    pub url: AString<'a>,
    /// What was found.
    pub value: UrlFetchValue<'a>,
}

/// The data for one URL: RFC 4467's string, `NIL` when the URL is not
/// valid for any reason, or RFC 5524's metadata items.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum UrlFetchValue<'a> {
    /// `nstring`.
    Simple(NString<'a>),
    /// `url-metadata = 1*(SP "(" url-metadata-el ")")`.
    Metadata(Vec<UrlMetadata<'a>>),
}

/// One RFC 5524 metadata item.
///
/// ```abnf
/// url-meta-bodystruct = "BODYPARTSTRUCTURE" SP body
/// url-meta-binary     = "BINARY" SP ( nstring / literal8 )
/// url-meta-body       = "BODY" SP nstring
/// ```
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum UrlMetadata<'a> {
    /// The part's structure, boxed for its size.
    BodyPartStructure(Box<BodyStructure<'a>>),
    /// The part as stored.
    Body(NString<'a>),
    /// The part with its Content-Transfer-Encoding undone, or `NIL` when
    /// that could not be done.
    Binary(NString8<'a>),
}
