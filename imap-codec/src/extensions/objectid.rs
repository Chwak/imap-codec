//! Object identifiers (RFC 8474) and `UNAUTHENTICATE` (RFC 8437).

use imap_types::extensions::objectid::{ObjectId, is_objectid_char};
use nom::{bytes::streaming::take_while_m_n, combinator::map};

use crate::decode::IMAPResult;

/// `objectid = 1*255(ALPHA / DIGIT / "_" / "-")`
pub(crate) fn objectid(input: &[u8]) -> IMAPResult<&[u8], ObjectId> {
    map(
        take_while_m_n(1, 255, is_objectid_char),
        |bytes: &[u8]| {
            // `is_objectid_char` admits ASCII only, so this is UTF-8, and the
            // length is bounded by `take_while_m_n`.
            ObjectId::unvalidated(std::str::from_utf8(bytes).unwrap())
        },
    )(input)
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

    /// RFC 8474 Section 7's examples, read and written back byte for byte.
    #[test]
    fn test_objectid_round_trips() {
        round_trip_command(b"3 FETCH 1:* (EMAILID THREADID)\r\n");
        round_trip_command(b"27 SEARCH EMAILID M6d99ac3275bb4e THREADID T64b478a75b7ea9\r\n");
        round_trip_command(b"3 STATUS foo (MAILBOXID)\r\n");
        round_trip_response(
            b"* 1 FETCH (EMAILID (M6d99ac3275bb4e) THREADID (T64b478a75b7ea9))\r\n",
        );
        round_trip_response(b"* 2 FETCH (EMAILID (M5fdc09b49ea703) THREADID NIL)\r\n");
        round_trip_response(b"* STATUS foo (MAILBOXID (F2212ea87-6097-4256-9d51-71338625))\r\n");
        round_trip_response(b"3 OK [MAILBOXID (F2212ea87-6097-4256-9d51-71338625)] Completed\r\n");
        round_trip_response(b"* OK [MAILBOXID (F2212ea87-6097-4256-9d51-71338625)] Ok\r\n");
    }

    #[test]
    fn test_objectid_refusals() {
        for line in [
            &b"3 SEARCH EMAILID M.1\r\n"[..],
            b"3 FETCH 1 (EMAILIDS)\r\n",
        ] {
            assert!(
                CommandCodec::default().decode(line).is_err(),
                "{} should not parse",
                String::from_utf8_lossy(line)
            );
        }
        assert!(
            ResponseCodec::default()
                .decode(b"* 1 FETCH (EMAILID M1)\r\n")
                .is_err(),
            "the parentheses are the rule's"
        );
    }

    /// RFC 8970 Section 3's commands and answers.
    #[test]
    fn test_preview_round_trips() {
        // One item is written without its parentheses, as for any item.
        round_trip_command(b"A1 FETCH 1 PREVIEW\r\n");
        round_trip_command(b"A4 FETCH 1 PREVIEW (LAZY)\r\n");
        round_trip_command(b"A2 FETCH 1:3 (UID PREVIEW (LAZY))\r\n");
        round_trip_response(b"* 1 FETCH (PREVIEW \"Hello, this is a preview\")\r\n");
        round_trip_response(b"* 2 FETCH (UID 4 PREVIEW NIL)\r\n");
        round_trip_response(b"* 3 FETCH (PREVIEW \"\")\r\n");
        assert!(
            CommandCodec::default()
                .decode(b"A3 FETCH 1 (PREVIEW (FAST))\r\n")
                .is_err(),
            "LAZY is the only modifier"
        );
    }

    /// RFC 8437 Section 2.
    #[test]
    fn test_unauthenticate_round_trips() {
        assert_eq!(
            round_trip_command(b"A UNAUTHENTICATE\r\n"),
            CommandBody::Unauthenticate
        );
    }
}
