use imap_types::{
    core::Vec1,
    sequence::{SeqOrUid, Sequence, SequenceSet, SequenceSetOrSaved},
};
use nom::{
    branch::alt,
    bytes::streaming::tag,
    combinator::{map, value},
    multi::separated_list1,
    sequence::tuple,
};

use crate::{core::nz_number, decode::IMAPResult};

/// `sequence-set = (seq-number / seq-range) ["," sequence-set]`
///
/// Note: See errata id: 261 TODO: Why the errata?
///
/// Set of seq-number values, regardless of order.
/// Servers MAY coalesce overlaps and/or execute the sequence in any order.
///
/// Example: a message sequence number set of
/// 2,4:7,9,12:* for a mailbox with 15 messages is
/// equivalent to 2,4,5,6,7,9,12,13,14,15
///
/// Example: a message sequence number set of *:4,5:7
/// for a mailbox with 10 messages is equivalent to
/// 10,9,8,7,6,5,4,5,6,7 and MAY be reordered and
/// overlap coalesced to be 4,5,6,7,8,9,10.
///
/// Simplified:
///
/// `sequence-set = (seq-number / seq-range) *("," (seq-number / seq-range))`
pub(crate) fn sequence_set(input: &[u8]) -> IMAPResult<&[u8], SequenceSet> {
    map(
        separated_list1(
            tag(b","),
            alt((
                // Ordering is important!
                map(seq_range, |(from, to)| Sequence::Range(from, to)),
                map(seq_number, Sequence::Single),
            )),
        ),
        |set| SequenceSet(Vec1::unvalidated(set)),
    )(input)
}

/// ```abnf
/// sequence-set     =/ seq-last-command
/// seq-last-command =  "$"
/// ```
///
/// RFC 5182 Section 3, as RFC 9051 Section 9 has it: where a command names
/// messages it may name them as `$`, the result a `SEARCH RETURN (SAVE)`
/// kept. `$` is the whole set and never one element of it.
pub(crate) fn sequence_set_or_saved(input: &[u8]) -> IMAPResult<&[u8], SequenceSetOrSaved> {
    alt((
        value(SequenceSetOrSaved::Saved, tag(b"$")),
        map(sequence_set, SequenceSetOrSaved::Set),
    ))(input)
}

/// `seq-range = seq-number ":" seq-number`
///
/// Two seq-number values and all values between these two regardless of order.
///
/// Example: 2:4 and 4:2 are equivalent and indicate values 2, 3, and 4.
///
/// Example: a unique identifier sequence range of 3291:* includes the UID
///          of the last message in the mailbox, even if that value is less than 3291.
pub(crate) fn seq_range(input: &[u8]) -> IMAPResult<&[u8], (SeqOrUid, SeqOrUid)> {
    let mut parser = tuple((seq_number, tag(b":"), seq_number));

    let (remaining, (from, _, to)) = parser(input)?;

    Ok((remaining, (from, to)))
}

/// `seq-number = nz-number / "*"`
///
/// Message sequence number (COPY, FETCH, STORE commands) or unique
/// identifier (UID COPY, UID FETCH, UID STORE commands).
///
/// "*" represents the largest number in use.
/// In the case of message sequence numbers, it is the number of messages in a non-empty mailbox.
/// In the case of unique identifiers, it is the unique identifier of the last message in the mailbox or,
/// if the mailbox is empty, the mailbox's current UIDNEXT value.
///
/// The server should respond with a tagged BAD response to a command that uses a message
/// sequence number greater than the number of messages in the selected mailbox.
/// This includes "*" if the selected mailbox is empty.
pub(crate) fn seq_number(input: &[u8]) -> IMAPResult<&[u8], SeqOrUid> {
    alt((
        map(nz_number, SeqOrUid::Value),
        value(SeqOrUid::Asterisk, tag(b"*")),
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{EncodeContext, EncodeIntoContext};

    /// RFC 5182 Section 2's examples, and `$` everywhere RFC 9051 lets a
    /// command name messages, each read and written back unchanged.
    #[test]
    fn test_searchres_commands_read_and_write_back() {
        use crate::{CommandCodec, decode::Decoder};

        for line in [
            // The date as the encoder writes it; RFC 5182's `1-Feb-1994` reads the same.
            &b"A282 SEARCH RETURN (SAVE) FLAGGED SINCE \"01-Feb-1994\" NOT FROM \"Smith\"\r\n"[..],
            b"A283 FETCH $ (UID INTERNALDATE FLAGS RFC822.SIZE)\r\n",
            b"A284 UID SEARCH RETURN (MIN MAX SAVE) UNSEEN\r\n",
            b"A285 UID STORE $ +FLAGS (\\Seen)\r\n",
            b"A286 UID COPY $ Trash\r\n",
            b"A287 MOVE $ Trash\r\n",
            b"A288 UID EXPUNGE $\r\n",
            b"A289 UID SEARCH UID $ SMALLER 4096\r\n",
            b"A290 SEARCH $ NOT DELETED\r\n",
        ] {
            let (rest, command) = CommandCodec::default().decode(line).unwrap_or_else(|e| {
                panic!("{} does not parse: {e:?}", String::from_utf8_lossy(line))
            });
            assert!(rest.is_empty());
            let mut ctx = EncodeContext::new();
            command.encode_ctx(&mut ctx).unwrap();
            assert_eq!(ctx.dump(), line, "{}", String::from_utf8_lossy(line));
        }
    }

    /// `$` is a whole sequence set, never an element of one.
    #[test]
    fn test_saved_is_the_whole_set() {
        use crate::{CommandCodec, decode::Decoder};

        assert_eq!(
            sequence_set_or_saved(b"$ ").unwrap().1,
            SequenceSetOrSaved::Saved
        );
        for line in [
            &b"A FETCH 1,$ (FLAGS)\r\n"[..],
            b"A FETCH $,1 (FLAGS)\r\n",
            b"A FETCH $:3 (FLAGS)\r\n",
            b"A COPY 1:$ Trash\r\n",
        ] {
            assert!(
                CommandCodec::default().decode(line).is_err(),
                "{} should not parse",
                String::from_utf8_lossy(line)
            );
        }
        assert_eq!(
            SequenceSetOrSaved::try_from("$").unwrap(),
            SequenceSetOrSaved::Saved
        );
        assert!(matches!(
            SequenceSetOrSaved::try_from("1:*").unwrap(),
            SequenceSetOrSaved::Set(_)
        ));
    }

    #[test]
    fn test_notsaved_code_reads_and_writes_back() {
        use crate::{ResponseCodec, decode::Decoder};

        let line: &[u8] = b"A284 OK [NOTSAVED] Search done, result not saved\r\n";
        let (_, response) = ResponseCodec::default().decode(line).unwrap();
        let mut ctx = EncodeContext::new();
        response.encode_ctx(&mut ctx).unwrap();
        assert_eq!(ctx.dump(), line);
    }

    #[test]
    fn test_encode_of_some_sequence_sets() {
        let tests = [
            (
                Sequence::Single(SeqOrUid::Value(1.try_into().unwrap())),
                b"1".as_ref(),
            ),
            (Sequence::Single(SeqOrUid::Asterisk), b"*".as_ref()),
            (
                Sequence::Range(SeqOrUid::Value(1.try_into().unwrap()), SeqOrUid::Asterisk),
                b"1:*".as_ref(),
            ),
        ];

        for (test, expected) in tests {
            let mut ctx = EncodeContext::new();
            test.encode_ctx(&mut ctx).unwrap();

            let out = ctx.dump();
            assert_eq!(*expected, out);
        }
    }

    #[test]
    fn test_parse_sequence_set() {
        let (rem, val) = sequence_set(b"1:*?").unwrap();
        println!("{rem:?}, {val:?}");

        let (rem, val) = sequence_set(b"1:*,5?").unwrap();
        println!("{rem:?}, {val:?}");
    }

    #[test]
    fn test_parse_seq_number() {
        // Must not be 0.
        assert!(seq_number(b"0?").is_err());

        let (rem, val) = seq_number(b"1?").unwrap();
        println!("{rem:?}, {val:?}");

        let (rem, val) = seq_number(b"*?").unwrap();
        println!("{rem:?}, {val:?}");
    }

    #[test]
    fn test_parse_seq_range() {
        // Must not be 0.
        assert!(seq_range(b"0:1?").is_err());

        assert_eq!(
            (
                SeqOrUid::Value(1.try_into().unwrap()),
                SeqOrUid::Value(2.try_into().unwrap())
            ),
            seq_range(b"1:2?").unwrap().1
        );
        assert_eq!(
            (SeqOrUid::Value(1.try_into().unwrap()), SeqOrUid::Asterisk),
            seq_range(b"1:*?").unwrap().1
        );
        assert_eq!(
            (SeqOrUid::Asterisk, SeqOrUid::Value(10.try_into().unwrap())),
            seq_range(b"*:10?").unwrap().1
        );
    }
}
