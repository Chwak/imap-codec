//! URLAUTH (RFC 4467) and its BINARY extension to URLFETCH (RFC 5524).

use abnf_core::streaming::sp;
use imap_types::{
    command::CommandBody,
    core::{Atom, NString8, Vec1},
    extensions::urlauth::{UrlFetchArg, UrlFetchData, UrlFetchValue, UrlMetadata},
    response::{Code, Data},
};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while1},
    combinator::{map, opt},
    multi::{many0, many1},
    sequence::{delimited, preceded, tuple},
};

use crate::{
    body::body,
    core::{astring, atom, base64, nstring},
    decode::IMAPResult,
    extensions::binary::literal8,
    mailbox::mailbox,
};

/// ```abnf
/// resp-text-code =/ "URLMECH" SP "INTERNAL" *(SP mechanism ["=" base64])
/// mechanism      = "INTERNAL" / 1*(ALPHA / DIGIT / "-" / ".")
/// ```
///
/// A mechanism is read by its own rule here, not as an atom, because an
/// atom would swallow the `=` and the key after it.
pub(crate) fn resp_code_urlmech(input: &[u8]) -> IMAPResult<&[u8], Code> {
    let mechanism = map(
        take_while1(|b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'),
        |bytes: &[u8]| {
            // Every byte is ASCII, and none is an atom-special.
            Atom::unvalidated(std::str::from_utf8(bytes).unwrap())
        },
    );
    map(
        preceded(
            tag_no_case(b"URLMECH INTERNAL"),
            many0(preceded(
                sp,
                tuple((mechanism, opt(preceded(tag(b"="), base64)))),
            )),
        ),
        |mechanisms| Code::UrlMech { mechanisms },
    )(input)
}

/// The three commands, as one alternative for `command-auth`.
///
/// ```abnf
/// command-auth =/ resetkey / genurlauth / urlfetch
/// ```
pub(crate) fn urlauth_command(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    alt((genurlauth, resetkey, urlfetch))(input)
}

/// ```abnf
/// genurlauth = "GENURLAUTH" 1*(SP url-rump SP mechanism)
/// url-rump   = astring
/// mechanism  = "INTERNAL" / 1*(ALPHA / DIGIT / "-" / ".")
/// ```
///
/// A mechanism is read as an atom, which admits more than the rule does;
/// which mechanisms exist is the server's to say.
pub(crate) fn genurlauth(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    map(
        preceded(
            tag_no_case(b"GENURLAUTH"),
            many1(tuple((preceded(sp, astring), preceded(sp, atom)))),
        ),
        |urls| CommandBody::GenUrlAuth {
            urls: Vec1::unvalidated(urls),
        },
    )(input)
}

/// `resetkey = "RESETKEY" [SP mailbox *(SP mechanism)]`
pub(crate) fn resetkey(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    map(
        preceded(
            tag_no_case(b"RESETKEY"),
            opt(tuple((preceded(sp, mailbox), many0(preceded(sp, atom))))),
        ),
        |named| match named {
            Some((mailbox, mechanisms)) => CommandBody::ResetKey {
                mailbox: Some(mailbox),
                mechanisms,
            },
            None => CommandBody::ResetKey {
                mailbox: None,
                mechanisms: Vec::new(),
            },
        },
    )(input)
}

/// ```abnf
/// urlfetch         = "URLFETCH" 1*(SP url-fetch-arg)
/// url-fetch-arg    = url-fetch-simple / url-fetch-ext
/// url-fetch-simple = url-full
/// url-fetch-ext    = "(" url-full *(SP url-fetch-param) ")"
/// url-fetch-param  = "BODY" / "BINARY" / "BODYPARTSTRUCTURE" / atom
/// url-full         = astring
/// ```
pub(crate) fn urlfetch(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    let arg = alt((
        map(
            delimited(
                tag(b"("),
                tuple((astring, many0(preceded(sp, atom)))),
                tag(b")"),
            ),
            |(url, params)| UrlFetchArg {
                url,
                params: Some(params),
            },
        ),
        map(astring, |url| UrlFetchArg { url, params: None }),
    ));
    map(
        preceded(tag_no_case(b"URLFETCH"), many1(preceded(sp, arg))),
        |urls| CommandBody::UrlFetch {
            urls: Vec1::unvalidated(urls),
        },
    )(input)
}

/// The two responses, as one alternative for `mailbox-data`.
pub(crate) fn urlauth_data(input: &[u8]) -> IMAPResult<&[u8], Data> {
    alt((genurlauth_response, urlfetch_response))(input)
}

/// `genurlauth-data = "*" SP "GENURLAUTH" 1*(SP url-full)`
fn genurlauth_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    map(
        preceded(tag_no_case(b"GENURLAUTH"), many1(preceded(sp, astring))),
        |urls| Data::GenUrlAuth {
            urls: Vec1::unvalidated(urls),
        },
    )(input)
}

/// ```abnf
/// urlfetch-data  = "*" SP "URLFETCH" 1*(SP (urldata-simple / urldata-ext))
/// urldata-simple = url-full SP nstring
/// urldata-ext    = url-full url-metadata
/// url-metadata   = 1*(SP "(" url-metadata-el ")")
/// ```
///
/// RFC 5524's ABNF puts a second `SP` before each item, inside
/// `urldata-simple` and `urldata-ext` as well as before them; servers send
/// one, and so does RFC 5524's own example, so one is what is read.
fn urlfetch_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let value = alt((
        map(preceded(sp, nstring), UrlFetchValue::Simple),
        map(
            many1(preceded(
                sp,
                delimited(tag(b"("), url_metadata_el, tag(b")")),
            )),
            UrlFetchValue::Metadata,
        ),
    ));
    let item = map(tuple((preceded(sp, astring), value)), |(url, value)| {
        UrlFetchData { url, value }
    });
    map(preceded(tag_no_case(b"URLFETCH"), many1(item)), |items| {
        Data::UrlFetch {
            items: Vec1::unvalidated(items),
        }
    })(input)
}

/// ```abnf
/// url-metadata-el     = url-meta-bodystruct / url-meta-body / url-meta-binary
/// url-meta-bodystruct = "BODYPARTSTRUCTURE" SP body
/// url-meta-binary     = "BINARY" SP ( nstring / literal8 )
/// url-meta-body       = "BODY" SP nstring
/// ```
fn url_metadata_el(input: &[u8]) -> IMAPResult<&[u8], UrlMetadata> {
    alt((
        map(
            preceded(tag_no_case(b"BODYPARTSTRUCTURE "), body(8)),
            |structure| UrlMetadata::BodyPartStructure(Box::new(structure)),
        ),
        map(preceded(tag_no_case(b"BODY "), nstring), UrlMetadata::Body),
        map(
            preceded(
                tag_no_case(b"BINARY "),
                alt((
                    map(nstring, NString8::NString),
                    map(literal8, NString8::Literal8),
                )),
            ),
            UrlMetadata::Binary,
        ),
    ))(input)
}

#[cfg(test)]
mod tests {
    use imap_types::{
        command::CommandBody,
        extensions::urlauth::{UrlFetchValue, UrlMetadata},
        response::{Data, Response},
    };

    use crate::{
        CommandCodec, ResponseCodec,
        decode::Decoder,
        encode::{EncodeContext, EncodeIntoContext},
    };

    fn round_trip_command(line: &[u8]) -> CommandBody<'_> {
        let (rest, command) = CommandCodec::default()
            .decode(line)
            .unwrap_or_else(|e| panic!("{}: {e:?}", String::from_utf8_lossy(line)));
        assert!(rest.is_empty());
        let mut ctx = EncodeContext::new();
        command.encode_ctx(&mut ctx).unwrap();
        assert_eq!(ctx.dump(), line, "{}", String::from_utf8_lossy(line));
        command.body
    }

    fn round_trip_response(line: &[u8]) -> Response<'_> {
        let (rest, response) = ResponseCodec::default()
            .decode(line)
            .unwrap_or_else(|e| panic!("{}: {e:?}", String::from_utf8_lossy(line)));
        assert!(rest.is_empty());
        let mut ctx = EncodeContext::new();
        response.encode_ctx(&mut ctx).unwrap();
        assert_eq!(ctx.dump(), line, "{}", String::from_utf8_lossy(line));
        response
    }

    /// RFC 4467's examples, read and written back byte for byte.
    #[test]
    fn test_urlauth_round_trips() {
        let body = round_trip_command(
            b"a GENURLAUTH \"imap://joe@example.com/INBOX/;uid=20/;section=1.2;urlauth=submit+fred\" INTERNAL\r\n",
        );
        assert!(matches!(body, CommandBody::GenUrlAuth { urls } if urls.as_ref().len() == 1));
        round_trip_command(
            b"b GENURLAUTH \"imap://joe@example.com/INBOX/;uid=20;urlauth=anonymous\" INTERNAL \"imap://joe@example.com/Drafts/;uid=3;urlauth=authuser\" INTERNAL\r\n",
        );
        let body = round_trip_command(b"c RESETKEY\r\n");
        assert!(matches!(body, CommandBody::ResetKey { mailbox: None, .. }));
        round_trip_command(b"d RESETKEY INBOX\r\n");
        round_trip_command(b"e RESETKEY Drafts INTERNAL\r\n");
        round_trip_command(
            b"f URLFETCH \"imap://joe@example.com/INBOX/;uid=20/;section=1.2;urlauth=submit+fred:internal:91354a473744909de610943775f92038\"\r\n",
        );
        let body = round_trip_command(b"g URLFETCH (\"imap://a@b/INBOX/;uid=1;urlauth=authuser:internal:00\" BINARY BODYPARTSTRUCTURE) \"imap://a@b/INBOX/;uid=2;urlauth=authuser:internal:00\"\r\n");
        let CommandBody::UrlFetch { urls } = body else {
            panic!("not a URLFETCH");
        };
        assert_eq!(urls.as_ref()[0].params.as_ref().map(Vec::len), Some(2));
        assert_eq!(urls.as_ref()[1].params, None);
        round_trip_command(
            b"h URLFETCH (\"imap://a@b/INBOX/;uid=1;urlauth=authuser:internal:00\")\r\n",
        );

        round_trip_response(
            b"* GENURLAUTH \"imap://joe@example.com/INBOX/;uid=20/;section=1.2;urlauth=submit+fred:internal:91354a473744909de610943775f92038\"\r\n",
        );
        round_trip_response(b"* URLFETCH \"imap://a@b/INBOX/;uid=1;urlauth=anonymous:internal:00\" {5}\r\nhello\r\n");
        round_trip_response(b"* URLFETCH \"imap://a@b/INBOX/;uid=1;urlauth=anonymous:internal:00\" NIL \"imap://a@b/INBOX/;uid=2;urlauth=anonymous:internal:00\" \"hi\"\r\n");
        let response = round_trip_response(
            b"* URLFETCH \"imap://a@b/INBOX/;uid=1/;section=1.1;urlauth=authuser:internal:00\" (BODYPARTSTRUCTURE (\"TEXT\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\" 11 0 NIL NIL NIL NIL)) (BINARY ~{11}\r\nhello world)\r\n",
        );
        let Response::Data(Data::UrlFetch { items }) = response else {
            panic!("not a URLFETCH");
        };
        let UrlFetchValue::Metadata(metadata) = &items.as_ref()[0].value else {
            panic!("not metadata");
        };
        assert!(matches!(metadata[0], UrlMetadata::BodyPartStructure(_)));
        assert!(matches!(metadata[1], UrlMetadata::Binary(_)));
        round_trip_response(b"* URLFETCH \"imap://a@b/INBOX/;uid=1;urlauth=authuser:internal:00\" (BODY \"x\") (BINARY NIL)\r\n");
        round_trip_response(b"* CAPABILITY IMAP4REV1 URLAUTH URLAUTH=BINARY\r\n");
        round_trip_response(b"* OK [URLMECH INTERNAL] Ok\r\n");
        round_trip_response(b"a33 OK [URLMECH INTERNAL XSAMPLE=P34OKhO7VEkCbsiYY8rGEg==] done\r\n");
        round_trip_response(b"a34 OK [URLMECH INTERNAL X-ONE X.TWO=] done\r\n");
    }

    #[test]
    fn test_urlauth_refusals() {
        for line in [
            &b"a GENURLAUTH\r\n"[..],
            b"a GENURLAUTH \"imap://a@b/INBOX/;uid=1;urlauth=anonymous\"\r\n",
            b"a URLFETCH\r\n",
            b"a URLFETCH (\"imap://a@b/INBOX/;uid=1\" BINARY\r\n",
        ] {
            assert!(
                CommandCodec::default().decode(line).is_err(),
                "{} should not parse",
                String::from_utf8_lossy(line)
            );
        }
        for line in [
            &b"* GENURLAUTH\r\n"[..],
            b"* URLFETCH \"imap://a@b/INBOX/;uid=1\"\r\n",
            b"* URLFETCH \"imap://a@b/INBOX/;uid=1\" (SIZE 3)\r\n",
        ] {
            assert!(
                ResponseCodec::default().decode(line).is_err(),
                "{} should not parse",
                String::from_utf8_lossy(line)
            );
        }
    }
}
