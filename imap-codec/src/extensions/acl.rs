//! IMAP4 Access Control List extension (RFC 4314).

use abnf_core::streaming::sp;
use imap_types::{command::CommandBody, response::Data};
use nom::{
    branch::alt,
    bytes::streaming::tag_no_case,
    combinator::map,
    multi::many0,
    sequence::{preceded, tuple},
};

use crate::{core::astring, decode::IMAPResult, mailbox::mailbox};

/// The five commands, as one alternative for `command-auth`.
///
/// ```abnf
/// command-auth =/ setacl / deleteacl / getacl / listrights / myrights
/// ```
pub(crate) fn acl_command(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    alt((setacl, deleteacl, getacl, listrights, myrights))(input)
}

/// ```abnf
/// setacl     = "SETACL" SP mailbox SP identifier SP mod-rights
/// identifier = astring
/// mod-rights = astring
/// ```
///
/// `mod-rights` is kept as written, its `+` or `-` included: which rights
/// exist is the server's to judge (RFC 4314 Section 3.1 answers an unknown
/// one with `BAD`), not the grammar's.
pub(crate) fn setacl(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    let mut parser = tuple((tag_no_case(b"SETACL "), mailbox, sp, astring, sp, astring));

    let (remaining, (_, mailbox, _, identifier, _, rights)) = parser(input)?;

    Ok((
        remaining,
        CommandBody::SetAcl {
            mailbox,
            identifier,
            rights,
        },
    ))
}

/// `deleteacl = "DELETEACL" SP mailbox SP identifier`
pub(crate) fn deleteacl(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    let mut parser = tuple((tag_no_case(b"DELETEACL "), mailbox, sp, astring));

    let (remaining, (_, mailbox, _, identifier)) = parser(input)?;

    Ok((
        remaining,
        CommandBody::DeleteAcl {
            mailbox,
            identifier,
        },
    ))
}

/// `getacl = "GETACL" SP mailbox`
pub(crate) fn getacl(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    map(preceded(tag_no_case(b"GETACL "), mailbox), |mailbox| {
        CommandBody::GetAcl { mailbox }
    })(input)
}

/// `listrights = "LISTRIGHTS" SP mailbox SP identifier`
pub(crate) fn listrights(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    let mut parser = tuple((tag_no_case(b"LISTRIGHTS "), mailbox, sp, astring));

    let (remaining, (_, mailbox, _, identifier)) = parser(input)?;

    Ok((
        remaining,
        CommandBody::ListRights {
            mailbox,
            identifier,
        },
    ))
}

/// `myrights = "MYRIGHTS" SP mailbox`
pub(crate) fn myrights(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    map(preceded(tag_no_case(b"MYRIGHTS "), mailbox), |mailbox| {
        CommandBody::MyRights { mailbox }
    })(input)
}

/// The three responses, as one alternative for `mailbox-data`.
///
/// ```abnf
/// mailbox-data =/ acl-data / listrights-data / myrights-data
/// ```
pub(crate) fn acl_data(input: &[u8]) -> IMAPResult<&[u8], Data> {
    alt((acl_response, listrights_response, myrights_response))(input)
}

/// ```abnf
/// acl-data = "ACL" SP mailbox *(SP identifier SP rights)
/// rights   = astring
/// ```
fn acl_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let mut parser = tuple((
        tag_no_case(b"ACL "),
        mailbox,
        many0(tuple((sp, astring, sp, astring))),
    ));

    let (remaining, (_, mailbox, entries)) = parser(input)?;

    Ok((
        remaining,
        Data::Acl {
            mailbox,
            entries: entries
                .into_iter()
                .map(|(_, identifier, _, rights)| (identifier, rights))
                .collect(),
        },
    ))
}

/// ```abnf
/// listrights-data = "LISTRIGHTS" SP mailbox SP identifier
///                   SP rights *(SP rights)
/// ```
fn listrights_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let mut parser = tuple((
        tag_no_case(b"LISTRIGHTS "),
        mailbox,
        sp,
        astring,
        sp,
        astring,
        many0(preceded(sp, astring)),
    ));

    let (remaining, (_, mailbox, _, identifier, _, required, optional)) = parser(input)?;

    Ok((
        remaining,
        Data::ListRights {
            mailbox,
            identifier,
            required,
            optional,
        },
    ))
}

/// `myrights-data = "MYRIGHTS" SP mailbox SP rights`
fn myrights_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let mut parser = tuple((tag_no_case(b"MYRIGHTS "), mailbox, sp, astring));

    let (remaining, (_, mailbox, _, rights)) = parser(input)?;

    Ok((remaining, Data::MyRights { mailbox, rights }))
}

#[cfg(test)]
mod tests {
    use imap_types::{command::CommandBody, response::Response};

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

    /// RFC 4314 Section 3's examples, read and written back byte for byte.
    #[test]
    fn test_acl_round_trips() {
        let body = round_trip_command(b"A001 SETACL INBOX/Drafts John lrswicda\r\n");
        assert!(matches!(body, CommandBody::SetAcl { .. }));
        round_trip_command(b"A002 SETACL INBOX Fred +k\r\n");
        round_trip_command(b"A003 SETACL \"Saved mail\" \"Jane Doe\" -wt\r\n");
        round_trip_command(b"A004 SETACL INBOX Fred \"\"\r\n");
        let body = round_trip_command(b"A005 DELETEACL INBOX Fred\r\n");
        assert!(matches!(body, CommandBody::DeleteAcl { .. }));
        let body = round_trip_command(b"A006 GETACL INBOX\r\n");
        assert!(matches!(body, CommandBody::GetAcl { .. }));
        let body = round_trip_command(b"A007 LISTRIGHTS ~/Mail/saved smith\r\n");
        assert!(matches!(body, CommandBody::ListRights { .. }));
        let body = round_trip_command(b"A008 MYRIGHTS INBOX\r\n");
        assert!(matches!(body, CommandBody::MyRights { .. }));

        round_trip_response(b"* ACL INBOX Fred rwipslxetad -Fred wetd $team w\r\n");
        round_trip_response(b"* ACL Archive\r\n");
        round_trip_response(b"* LISTRIGHTS ~/Mail/saved smith la r swicdkxte\r\n");
        round_trip_response(b"* LISTRIGHTS INBOX \"a b\" \"\"\r\n");
        round_trip_response(b"* MYRIGHTS INBOX rwiptsldaex\r\n");
        round_trip_response(b"* CAPABILITY IMAP4REV1 ACL RIGHTS=texk\r\n");
    }

    #[test]
    fn test_acl_refusals() {
        for line in [
            &b"A1 SETACL INBOX Fred\r\n"[..],
            b"A1 DELETEACL INBOX\r\n",
            b"A1 GETACL\r\n",
            b"A1 LISTRIGHTS INBOX\r\n",
            b"A1 MYRIGHTS INBOX Fred\r\n",
        ] {
            assert!(
                CommandCodec::default().decode(line).is_err(),
                "{} should not parse",
                String::from_utf8_lossy(line)
            );
        }
        for line in [
            &b"* ACL INBOX Fred\r\n"[..],
            b"* LISTRIGHTS INBOX smith\r\n",
            b"* MYRIGHTS INBOX\r\n",
        ] {
            assert!(
                ResponseCodec::default().decode(line).is_err(),
                "{} should not parse",
                String::from_utf8_lossy(line)
            );
        }
    }
}
