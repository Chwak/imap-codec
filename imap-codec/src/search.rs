use abnf_core::streaming::sp;
use imap_types::{
    command::CommandBody,
    core::{Charset, Vec1},
    extensions::uidplus::UidSet,
    response::Data,
    search::{EsearchResponse, PartialRange, SearchKey, SearchReturnData, SearchReturnOption},
};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::{map, map_opt, opt, value},
    multi::{many0, separated_list0, separated_list1},
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
};

#[cfg(feature = "ext_condstore_qresync")]
use crate::extensions::condstore_qresync::{mod_sequence_value, search_modsequence};
use crate::{
    core::{astring, atom, charset, number, nz_number, tag_imap},
    datetime::date,
    decode::{IMAPErrorKind, IMAPParseError, IMAPResult},
    extensions::{objectid::objectid, uidplus::uid_set},
    fetch::header_fld_name,
    sequence::sequence_set_or_saved,
};

/// `search = "SEARCH" [search-return-opts] [SP "CHARSET" SP charset] 1*(SP search-key)`
///
/// Note: CHARSET argument MUST be registered with IANA
///
/// errata id: 261
///
/// RFC 4731 Section 3.1 extends the rule with `search-return-opts`, which
/// RFC 9051 Section 6.4.4 carries into IMAP4rev2. The options come before
/// the charset, and their presence — not their content — is what makes
/// the answer an `ESEARCH` rather than a `SEARCH`: `SEARCH RETURN ()` is
/// defined to mean `RETURN (ALL)` and is a different command from a
/// `SEARCH` with no `RETURN` at all.
pub(crate) fn search(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    let mut parser = tuple((
        tag_no_case(b"SEARCH"),
        opt(search_return_opts),
        opt(map(
            tuple((sp, tag_no_case(b"CHARSET"), sp, charset)),
            |(_, _, _, charset)| charset,
        )),
        sp,
        map(separated_list1(sp, search_key(9)), Vec1::unvalidated),
    ));

    let (remaining, (_, return_options, charset, _, criteria)) = parser(input)?;

    Ok((
        remaining,
        CommandBody::Search {
            return_options,
            charset,
            criteria,
            uid: false,
        },
    ))
}

/// ```abnf
/// search-return-opts = SP "RETURN" SP "(" [search-return-opt *(SP search-return-opt)] ")"
/// ```
///
/// RFC 4731 Section 3.1. An empty list parses to an empty `Vec`, which is
/// not the same as the rule being absent; the caller keeps that apart by
/// wrapping this in `opt`.
pub(crate) fn search_return_opts(input: &[u8]) -> IMAPResult<&[u8], Vec<SearchReturnOption>> {
    preceded(
        tuple((sp, tag_no_case(b"RETURN"), sp)),
        delimited(tag(b"("), separated_list0(sp, search_return_opt), tag(b")")),
    )(input)
}

/// ```abnf
/// search-return-opt = "MIN" / "MAX" / "ALL" / "COUNT" / search-ret-opt-ext
/// ```
///
/// `search-ret-opt-ext` is deliberately not accepted: an option this
/// server cannot answer must be refused as the syntax error RFC 4731
/// Section 3.1 makes it ("the server MUST return a tagged BAD response"),
/// and accepting it here would leave the caller unable to tell an option
/// it understands from one it does not.
pub(crate) fn search_return_opt(input: &[u8]) -> IMAPResult<&[u8], SearchReturnOption> {
    alt((
        value(SearchReturnOption::Min, tag_no_case(b"MIN")),
        // Before MAX and ALL, neither of which is a prefix of the other,
        // but after nothing: the four RFC 4731 names and the three RFC
        // 5267 ones are distinct words.
        value(SearchReturnOption::Max, tag_no_case(b"MAX")),
        value(SearchReturnOption::All, tag_no_case(b"ALL")),
        value(SearchReturnOption::Count, tag_no_case(b"COUNT")),
        map(
            preceded(tuple((tag_no_case(b"PARTIAL"), sp)), partial_range),
            SearchReturnOption::Partial,
        ),
        value(SearchReturnOption::Update, tag_no_case(b"UPDATE")),
        value(SearchReturnOption::Context, tag_no_case(b"CONTEXT")),
        // RFC 5182 Section 3.
        value(SearchReturnOption::Save, tag_no_case(b"SAVE")),
    ))(input)
}

/// ```abnf
/// partial-range = nz-number ":" nz-number
/// ```
///
/// RFC 5267 Section 4.4. Both ends are `nz-number` and neither may be
/// `*`: `PARTIAL 1:*` and `PARTIAL *:1` are syntax errors, and so is a
/// bare `PARTIAL 1`. That is not pedantry — a server that guessed at
/// what `1:*` meant would answer a different question from the one the
/// next server answers, and the whole point of the option is that a
/// client can page through a result the same way everywhere.
pub(crate) fn partial_range(input: &[u8]) -> IMAPResult<&[u8], PartialRange> {
    map(
        separated_pair(nz_number, tag(b":"), nz_number),
        |(from, to)| PartialRange::new(from, to),
    )(input)
}

/// ```abnf
/// search-key = "ALL" /
///              "ANSWERED" /
///              "BCC" SP astring /
///              "BEFORE" SP date /
///              "BODY" SP astring /
///              "CC" SP astring /
///              "DELETED" /
///              "FLAGGED" /
///              "FROM" SP astring /
///              "KEYWORD" SP flag-keyword /
///              "NEW" /
///              "OLD" /
///              "ON" SP date /
///              "RECENT" /
///              "SEEN" /
///              "SINCE" SP date /
///              "SUBJECT" SP astring /
///              "TEXT" SP astring /
///              "TO" SP astring /
///              "UNANSWERED" /
///              "UNDELETED" /
///              "UNFLAGGED" /
///              "UNKEYWORD" SP flag-keyword /
///              "UNSEEN" /
///                ; Above this line were in [IMAP2]
///              "DRAFT" /
///              "HEADER" SP header-fld-name SP astring /
///              "LARGER" SP number /
///              "NOT" SP search-key /
///              "OR" SP search-key SP search-key /
///              "SENTBEFORE" SP date /
///              "SENTON" SP date /
///              "SENTSINCE" SP date /
///              "SMALLER" SP number /
///              "UID" SP sequence-set /
///              "UNDRAFT" /
///              search-modsequence / ; RFC 7162
///              sequence-set /
///              "(" search-key *(SP search-key) ")"
/// ```
///
/// This parser is recursively defined. Thus, in order to not overflow the stack,
/// it is needed to limit how may recursions are allowed. (8 should suffice).
pub(crate) fn search_key(
    remaining_recursions: usize,
) -> impl Fn(&[u8]) -> IMAPResult<&[u8], SearchKey> {
    move |input: &[u8]| search_key_limited(input, remaining_recursions)
}

fn search_key_limited(input: &[u8], remaining_recursion: usize) -> IMAPResult<&[u8], SearchKey> {
    if remaining_recursion == 0 {
        return Err(nom::Err::Failure(IMAPParseError {
            input,
            kind: IMAPErrorKind::RecursionLimitExceeded,
        }));
    }

    let search_key = |input| search_key_limited(input, remaining_recursion.saturating_sub(1));

    alt((
        alt((
            value(SearchKey::All, tag_no_case(b"ALL")),
            value(SearchKey::Answered, tag_no_case(b"ANSWERED")),
            map(tuple((tag_no_case(b"BCC"), sp, astring)), |(_, _, val)| {
                SearchKey::Bcc(val)
            }),
            map(
                tuple((tag_no_case(b"BEFORE"), sp, map_opt(date, |date| date))),
                |(_, _, date)| SearchKey::Before(date),
            ),
            map(tuple((tag_no_case(b"BODY"), sp, astring)), |(_, _, val)| {
                SearchKey::Body(val)
            }),
            map(tuple((tag_no_case(b"CC"), sp, astring)), |(_, _, val)| {
                SearchKey::Cc(val)
            }),
            value(SearchKey::Deleted, tag_no_case(b"DELETED")),
            value(SearchKey::Flagged, tag_no_case(b"FLAGGED")),
            map(tuple((tag_no_case(b"FROM"), sp, astring)), |(_, _, val)| {
                SearchKey::From(val)
            }),
            map(
                // Note: `flag_keyword` parser returns `Flag`. Because Rust does not have first-class enum variants
                // it is not possible to fix SearchKey(Flag::Keyword), but only SearchKey(Flag).
                // Thus `SearchKey::Keyword(Atom)` is used instead. This is, why we use also `atom` parser here and not `flag_keyword` parser.
                tuple((tag_no_case(b"KEYWORD"), sp, atom)),
                |(_, _, val)| SearchKey::Keyword(val),
            ),
            value(SearchKey::New, tag_no_case(b"NEW")),
            value(SearchKey::Old, tag_no_case(b"OLD")),
            map(
                tuple((tag_no_case(b"ON"), sp, map_opt(date, |date| date))),
                |(_, _, date)| SearchKey::On(date),
            ),
            value(SearchKey::Recent, tag_no_case(b"RECENT")),
            value(SearchKey::Seen, tag_no_case(b"SEEN")),
            map(
                tuple((tag_no_case(b"SINCE"), sp, map_opt(date, |date| date))),
                |(_, _, date)| SearchKey::Since(date),
            ),
            map(
                tuple((tag_no_case(b"SUBJECT"), sp, astring)),
                |(_, _, val)| SearchKey::Subject(val),
            ),
            map(tuple((tag_no_case(b"TEXT"), sp, astring)), |(_, _, val)| {
                SearchKey::Text(val)
            }),
            map(tuple((tag_no_case(b"TO"), sp, astring)), |(_, _, val)| {
                SearchKey::To(val)
            }),
            // RFC 8474 Section 7.
            map(
                preceded(tag_no_case(b"EMAILID "), objectid),
                SearchKey::EmailId,
            ),
            map(
                preceded(tag_no_case(b"THREADID "), objectid),
                SearchKey::ThreadId,
            ),
        )),
        alt((
            value(SearchKey::Unanswered, tag_no_case(b"UNANSWERED")),
            value(SearchKey::Undeleted, tag_no_case(b"UNDELETED")),
            value(SearchKey::Unflagged, tag_no_case(b"UNFLAGGED")),
            map(
                // Note: `flag_keyword` parser returns `Flag`. Because Rust does not have first-class enum variants
                // it is not possible to fix SearchKey(Flag::Keyword), but only SearchKey(Flag).
                // Thus `SearchKey::Keyword(Atom)` is used instead. This is, why we use also `atom` parser here and not `flag_keyword` parser.
                tuple((tag_no_case(b"UNKEYWORD"), sp, atom)),
                |(_, _, val)| SearchKey::Unkeyword(val),
            ),
            value(SearchKey::Unseen, tag_no_case(b"UNSEEN")),
            value(SearchKey::Draft, tag_no_case(b"DRAFT")),
            map(
                tuple((tag_no_case(b"HEADER"), sp, header_fld_name, sp, astring)),
                |(_, _, key, _, val)| SearchKey::Header(key, val),
            ),
            map(
                tuple((tag_no_case(b"LARGER"), sp, number)),
                |(_, _, val)| SearchKey::Larger(val),
            ),
            map(
                tuple((tag_no_case(b"NOT"), sp, search_key)),
                |(_, _, val)| SearchKey::Not(Box::new(val)),
            ),
            map(
                tuple((tag_no_case(b"OR"), sp, search_key, sp, search_key)),
                |(_, _, alt1, _, alt2)| SearchKey::Or(Box::new(alt1), Box::new(alt2)),
            ),
            map(
                tuple((tag_no_case(b"SENTBEFORE"), sp, map_opt(date, |date| date))),
                |(_, _, date)| SearchKey::SentBefore(date),
            ),
            map(
                tuple((tag_no_case(b"SENTON"), sp, map_opt(date, |date| date))),
                |(_, _, date)| SearchKey::SentOn(date),
            ),
            map(
                tuple((tag_no_case(b"SENTSINCE"), sp, map_opt(date, |date| date))),
                |(_, _, date)| SearchKey::SentSince(date),
            ),
            map(
                tuple((tag_no_case(b"SMALLER"), sp, number)),
                |(_, _, val)| SearchKey::Smaller(val),
            ),
            map(
                tuple((tag_no_case(b"UID"), sp, sequence_set_or_saved)),
                |(_, _, val)| SearchKey::Uid(val),
            ),
            value(SearchKey::Undraft, tag_no_case(b"UNDRAFT")),
            #[cfg(feature = "ext_condstore_qresync")]
            map(search_modsequence, |(entry, modseq)| {
                SearchKey::ModSequence { entry, modseq }
            }),
            map(sequence_set_or_saved, SearchKey::SequenceSet),
            map(
                delimited(tag(b"("), separated_list1(sp, search_key), tag(b")")),
                |val| SearchKey::And(Vec1::unvalidated(val)),
            ),
        )),
    ))(input)
}

/// ```abnf
/// search-criteria = charset 1*(SP search-key)
/// ```
pub(crate) fn search_criteria(input: &[u8]) -> IMAPResult<&[u8], (Charset, Vec1<SearchKey>)> {
    let mut parser = separated_pair(
        charset,
        sp,
        map(separated_list1(sp, search_key(9)), Vec1::unvalidated),
    );

    let (remaining, (charset, search_keys)) = parser(input)?;

    Ok((remaining, (charset, search_keys)))
}

/// ```abnf
/// esearch-response  = "ESEARCH" [search-correlator] [SP "UID"]
///                     *(SP search-return-data)
/// search-correlator = SP "(" "TAG" SP tag-string ")"
/// ```
///
/// RFC 4731 Section 3.2. The correlator is the point of the response: a
/// client that pipelined several searches has no other way to tell the
/// answers apart, because an untagged `SEARCH` carries no tag.
pub(crate) fn esearch_response(input: &[u8]) -> IMAPResult<&[u8], Data> {
    let mut parser = tuple((
        tag_no_case(b"ESEARCH"),
        opt(delimited(
            tuple((sp, tag(b"("), tag_no_case(b"TAG"), sp)),
            // `tag-string` is an astring. A tag is the subset of it a
            // command could have carried, so reading it as one refuses a
            // correlator that answers no command anybody could have sent;
            // both spellings an astring has for such a string are taken,
            // because servers differ on whether they quote it.
            alt((delimited(tag(b"\""), tag_imap, tag(b"\"")), tag_imap)),
            tag(b")"),
        )),
        opt(preceded(sp, tag_no_case(b"UID"))),
        many0(preceded(sp, search_return_data)),
    ));

    let (remaining, (_, correlator, uid, items)) = parser(input)?;

    Ok((
        remaining,
        Data::Esearch(EsearchResponse {
            correlator,
            uid: uid.is_some(),
            items,
        }),
    ))
}

/// ```abnf
/// search-return-data = "MIN" SP nz-number /
///                      "MAX" SP nz-number /
///                      "ALL" SP sequence-set /
///                      "COUNT" SP number
///
/// search-return-data =/ "MODSEQ" SP mod-sequence-value    ; RFC 7162
/// ```
pub(crate) fn search_return_data(input: &[u8]) -> IMAPResult<&[u8], SearchReturnData> {
    alt((
        map(
            preceded(tuple((tag_no_case(b"MIN"), sp)), nz_number),
            SearchReturnData::Min,
        ),
        map(
            preceded(tuple((tag_no_case(b"MAX"), sp)), nz_number),
            SearchReturnData::Max,
        ),
        map(
            preceded(tuple((tag_no_case(b"ALL"), sp)), uid_set),
            SearchReturnData::All,
        ),
        map(
            preceded(tuple((tag_no_case(b"COUNT"), sp)), number),
            SearchReturnData::Count,
        ),
        #[cfg(feature = "ext_condstore_qresync")]
        map(
            preceded(tuple((tag_no_case(b"MODSEQ"), sp)), mod_sequence_value),
            SearchReturnData::ModSeq,
        ),
        map(
            preceded(
                tuple((tag_no_case(b"PARTIAL"), sp, tag(b"("))),
                terminated(
                    separated_pair(
                        partial_range,
                        sp,
                        alt((map(uid_set, Some), value(None, tag_no_case(b"NIL")))),
                    ),
                    tag(b")"),
                ),
            ),
            |(range, results)| SearchReturnData::Partial(range, results),
        ),
        map(context_update(b"ADDTO"), |(position, set)| {
            SearchReturnData::AddTo(position, set)
        }),
        map(context_update(b"REMOVEFROM"), |(position, set)| {
            SearchReturnData::RemoveFrom(position, set)
        }),
    ))(input)
}

/// ```abnf
/// "ADDTO" SP "(" context-position SP uid-set ")"
/// "REMOVEFROM" SP "(" context-position SP uid-set ")"
/// context-position = number
/// ```
///
/// RFC 5267 Sections 4.3.1 and 4.3.2, which have the same shape and
/// differ only in the word. The position is a plain `number` and may be
/// zero: a search left open without `CONTEXT` has no result stored to
/// count positions in, and zero is what says so.
fn context_update(word: &'static [u8]) -> impl FnMut(&[u8]) -> IMAPResult<&[u8], (u32, UidSet)> {
    move |input| {
        preceded(
            tuple((tag_no_case(word), sp, tag(b"("))),
            terminated(separated_pair(number, sp, uid_set), tag(b")")),
        )(input)
    }
}

#[cfg(test)]
mod tests {
    use imap_types::{
        core::{AString, Atom},
        datetime::NaiveDate,
        sequence::{Sequence, SequenceSet},
    };

    use super::*;
    use crate::testing::known_answer_test_encode;

    #[test]
    fn test_parse_search() {
        use imap_types::{
            search::SearchKey::*,
            sequence::{SeqOrUid::Value, Sequence::*, SequenceSet as SequenceSetData},
        };

        let (_rem, val) = search(b"search (uid 5)???").unwrap();
        assert_eq!(
            val,
            CommandBody::Search {
                return_options: None,
                charset: None,
                criteria: Vec1::from(And(Vec1::from(Uid(SequenceSetData(
                    vec![Single(Value(5.try_into().unwrap()))]
                        .try_into()
                        .unwrap()
                )
                .into())))),
                uid: false,
            }
        );

        let (_rem, val) = search(b"search (uid 5 or uid 5 (uid 1 uid 2) not uid 5)???").unwrap();
        let expected = CommandBody::Search {
            return_options: None,
            charset: None,
            criteria: Vec1::from(And(vec![
                Uid(SequenceSetData(
                    vec![Single(Value(5.try_into().unwrap()))]
                        .try_into()
                        .unwrap(),
                )
                .into()),
                Or(
                    Box::new(Uid(SequenceSetData(
                        vec![Single(Value(5.try_into().unwrap()))]
                            .try_into()
                            .unwrap(),
                    )
                    .into())),
                    Box::new(And(vec![
                        Uid(SequenceSetData(
                            vec![Single(Value(1.try_into().unwrap()))]
                                .try_into()
                                .unwrap(),
                        )
                        .into()),
                        Uid(SequenceSetData(
                            vec![Single(Value(2.try_into().unwrap()))]
                                .try_into()
                                .unwrap(),
                        )
                        .into()),
                    ]
                    .try_into()
                    .unwrap())),
                ),
                Not(Box::new(Uid(SequenceSetData(
                    vec![Single(Value(5.try_into().unwrap()))]
                        .try_into()
                        .unwrap(),
                )
                .into()))),
            ]
            .try_into()
            .unwrap())),
            uid: false,
        };
        assert_eq!(val, expected);
    }

    #[test]
    fn test_parse_search_key() {
        assert!(search_key(1)(b"1:5|").is_ok());
        assert!(search_key(1)(b"(1:5)|").is_err());
        assert!(search_key(2)(b"(1:5)|").is_ok());
        assert!(search_key(2)(b"((1:5))|").is_err());
    }

    #[test]
    fn test_encode_search_key() {
        let tests = [
            (
                SearchKey::And(Vec1::try_from(vec![SearchKey::Answered]).unwrap()),
                b"(ANSWERED)".as_ref(),
            ),
            (
                SearchKey::And(Vec1::try_from(vec![SearchKey::Answered, SearchKey::Seen]).unwrap()),
                b"(ANSWERED SEEN)".as_ref(),
            ),
            (
                SearchKey::SequenceSet(SequenceSet::try_from(1).unwrap().into()),
                b"1",
            ),
            (SearchKey::All, b"ALL"),
            (SearchKey::Answered, b"ANSWERED"),
            (SearchKey::Bcc(AString::try_from("A").unwrap()), b"BCC A"),
            (
                SearchKey::Before(
                    NaiveDate::try_from(chrono::NaiveDate::from_ymd_opt(2023, 4, 12).unwrap())
                        .unwrap(),
                ),
                b"BEFORE \"12-Apr-2023\"",
            ),
            (SearchKey::Body(AString::try_from("A").unwrap()), b"BODY A"),
            (SearchKey::Cc(AString::try_from("A").unwrap()), b"CC A"),
            (SearchKey::Deleted, b"DELETED"),
            (SearchKey::Draft, b"DRAFT"),
            (SearchKey::Flagged, b"FLAGGED"),
            (SearchKey::From(AString::try_from("A").unwrap()), b"FROM A"),
            (
                SearchKey::Header(
                    AString::try_from("A").unwrap(),
                    AString::try_from("B").unwrap(),
                ),
                b"HEADER A B",
            ),
            (
                SearchKey::Keyword(Atom::try_from("A").unwrap()),
                b"KEYWORD A",
            ),
            (SearchKey::Larger(42), b"LARGER 42"),
            (SearchKey::New, b"NEW"),
            (SearchKey::Not(Box::new(SearchKey::New)), b"NOT NEW"),
            (SearchKey::Old, b"OLD"),
            (
                SearchKey::On(
                    NaiveDate::try_from(chrono::NaiveDate::from_ymd_opt(2023, 4, 12).unwrap())
                        .unwrap(),
                ),
                b"ON \"12-Apr-2023\"",
            ),
            (
                SearchKey::Or(Box::new(SearchKey::New), Box::new(SearchKey::Recent)),
                b"OR NEW RECENT",
            ),
            (SearchKey::Recent, b"RECENT"),
            (SearchKey::Seen, b"SEEN"),
            (
                SearchKey::SentBefore(
                    NaiveDate::try_from(chrono::NaiveDate::from_ymd_opt(2023, 4, 12).unwrap())
                        .unwrap(),
                ),
                b"SENTBEFORE \"12-Apr-2023\"",
            ),
            (
                SearchKey::SentOn(
                    NaiveDate::try_from(chrono::NaiveDate::from_ymd_opt(2023, 4, 12).unwrap())
                        .unwrap(),
                ),
                b"SENTON \"12-Apr-2023\"",
            ),
            (
                SearchKey::SentSince(
                    NaiveDate::try_from(chrono::NaiveDate::from_ymd_opt(2023, 4, 12).unwrap())
                        .unwrap(),
                ),
                b"SENTSINCE \"12-Apr-2023\"",
            ),
            (
                SearchKey::Since(
                    NaiveDate::try_from(chrono::NaiveDate::from_ymd_opt(2023, 4, 12).unwrap())
                        .unwrap(),
                ),
                b"SINCE \"12-Apr-2023\"",
            ),
            (SearchKey::Smaller(1337), b"SMALLER 1337"),
            (
                SearchKey::Subject(AString::try_from("A").unwrap()),
                b"SUBJECT A",
            ),
            (SearchKey::Text(AString::try_from("A").unwrap()), b"TEXT A"),
            (SearchKey::To(AString::try_from("A").unwrap()), b"TO A"),
            (
                SearchKey::Uid(SequenceSet::from(Sequence::try_from(1..).unwrap()).into()),
                b"UID 1:*",
            ),
            (SearchKey::Unanswered, b"UNANSWERED"),
            (SearchKey::Undeleted, b"UNDELETED"),
            (SearchKey::Undraft, b"UNDRAFT"),
            (SearchKey::Unflagged, b"UNFLAGGED"),
            (
                SearchKey::Unkeyword(Atom::try_from("A").unwrap()),
                b"UNKEYWORD A",
            ),
            (SearchKey::Unseen, b"UNSEEN"),
        ];

        for test in tests {
            known_answer_test_encode(test);
        }
    }
}
