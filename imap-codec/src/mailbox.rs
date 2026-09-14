use abnf_core::streaming::{dquote, sp};
use imap_types::{
    core::{QuotedChar, Vec1},
    flag::FlagNameAttribute,
    mailbox::{
        ListCharString, ListExtendedItem, ListMailbox, ListPatterns, ListReturnOption,
        ListSelectOption, Mailbox,
    },
    response::Data,
    utils::indicators::is_list_char,
};
#[cfg(feature = "ext_condstore_qresync")]
use nom::character::streaming::char;
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case, take_while1},
    combinator::{map, opt, value, verify},
    multi::{many0, separated_list0, separated_list1},
    sequence::{delimited, preceded, terminated, tuple},
};

#[cfg(feature = "ext_condstore_qresync")]
use crate::extensions::condstore_qresync::search_sort_mod_seq;
#[cfg(feature = "ext_metadata")]
use crate::extensions::metadata::metadata_resp;
#[cfg(feature = "ext_namespace")]
use crate::extensions::namespace::namespace_response;
use crate::{
    core::{astring, nil, number, nz_number, quoted_char, string},
    decode::IMAPResult,
    extensions::{
        quota::{quota_response, quotaroot_response},
        thread::thread_data,
    },
    flag::{flag_list, mbx_list_flags},
    search::esearch_response,
    status::{status_att, status_att_list},
};

/// `list-mailbox = 1*list-char / string`
pub(crate) fn list_mailbox(input: &[u8]) -> IMAPResult<&[u8], ListMailbox> {
    alt((
        map(take_while1(is_list_char), |bytes: &[u8]| {
            // # Safety
            //
            // `unwrap` is safe here, because `is_list_char` enforces that the bytes ...
            //   * contain ASCII-only characters, i.e., `from_utf8` will return `Ok`.
            //   * are valid according to `ListCharString::verify()`, i.e., `unvalidated` is safe.
            ListMailbox::Token(ListCharString::unvalidated(
                std::str::from_utf8(bytes).unwrap(),
            ))
        }),
        map(string, ListMailbox::String),
    ))(input)
}

/// ```abnf
/// mbox-or-pat = list-mailbox / patterns
/// patterns    = "(" list-mailbox *(SP list-mailbox) ")"
/// ```
pub(crate) fn list_patterns(input: &[u8]) -> IMAPResult<&[u8], ListPatterns> {
    alt((
        map(
            delimited(tag(b"("), separated_list1(sp, list_mailbox), tag(b")")),
            |patterns| ListPatterns::Several(Vec1::unvalidated(patterns)),
        ),
        map(list_mailbox, ListPatterns::One),
    ))(input)
}

/// ```abnf
/// list-select-opts = "(" [
///                      (*(list-select-opt SP) list-select-base-opt
///                       *(SP list-select-opt))
///                      / (list-select-independent-opt
///                       *(SP list-select-independent-opt))
///                    ] ")"
/// ```
///
/// RFC 5258 Section 6. Read as a list in any order and then checked, which
/// is what the rule says once its alternatives are unfolded: empty, or
/// holding a base option, or holding independent options only. So
/// `(RECURSIVEMATCH)` does not parse, and neither does `(RECURSIVEMATCH
/// REMOTE)`, which RFC 5258 Section 3.1 has the server refuse with `BAD`.
pub(crate) fn list_select_opts(input: &[u8]) -> IMAPResult<&[u8], Vec<ListSelectOption>> {
    verify(
        delimited(tag(b"("), separated_list0(sp, list_select_opt), tag(b")")),
        |options: &Vec<ListSelectOption>| ListSelectOption::valid_combination(options),
    )(input)
}

/// ```abnf
/// list-select-opt = list-select-base-opt / list-select-independent-opt
///                   / list-select-mod-opt
/// ```
///
/// `option-extension` is not accepted; see [`ListSelectOption`].
pub(crate) fn list_select_opt(input: &[u8]) -> IMAPResult<&[u8], ListSelectOption> {
    alt((
        value(ListSelectOption::Subscribed, tag_no_case(b"SUBSCRIBED")),
        value(ListSelectOption::Remote, tag_no_case(b"REMOTE")),
        value(
            ListSelectOption::RecursiveMatch,
            tag_no_case(b"RECURSIVEMATCH"),
        ),
        value(ListSelectOption::SpecialUse, tag_no_case(b"SPECIAL-USE")),
    ))(input)
}

/// ```abnf
/// list-return-opts = "RETURN" SP "(" [return-option *(SP return-option)] ")"
/// ```
pub(crate) fn list_return_opts(input: &[u8]) -> IMAPResult<&[u8], Vec<ListReturnOption>> {
    preceded(
        tuple((tag_no_case(b"RETURN"), sp)),
        delimited(tag(b"("), separated_list0(sp, list_return_opt), tag(b")")),
    )(input)
}

/// ```abnf
/// return-option =  "SUBSCRIBED" / "CHILDREN" / option-extension
/// return-option =/ "STATUS" SP "(" status-att *(SP status-att) ")"  ; RFC 5819
/// return-option =/ "SPECIAL-USE"                                    ; RFC 6154
/// ```
pub(crate) fn list_return_opt(input: &[u8]) -> IMAPResult<&[u8], ListReturnOption> {
    alt((
        value(ListReturnOption::Subscribed, tag_no_case(b"SUBSCRIBED")),
        value(ListReturnOption::Children, tag_no_case(b"CHILDREN")),
        map(
            preceded(
                tuple((tag_no_case(b"STATUS"), sp)),
                delimited(tag(b"("), separated_list1(sp, status_att), tag(b")")),
            ),
            |items| ListReturnOption::Status(Vec1::unvalidated(items)),
        ),
        value(ListReturnOption::SpecialUse, tag_no_case(b"SPECIAL-USE")),
    ))(input)
}

/// ```abnf
/// mbox-list-extended = "(" [mbox-list-extended-item
///                      *(SP mbox-list-extended-item)] ")"
/// ```
pub(crate) fn mbox_list_extended(input: &[u8]) -> IMAPResult<&[u8], Vec<ListExtendedItem>> {
    delimited(
        tag(b"("),
        separated_list0(sp, mbox_list_extended_item),
        tag(b")"),
    )(input)
}

/// ```abnf
/// childinfo-extended-item = "CHILDINFO" SP "("
///                           list-select-base-opt-quoted
///                           *(SP list-select-base-opt-quoted) ")"
/// oldname-extended-item   = "OLDNAME" SP "(" mailbox ")"
/// ```
///
/// The tag is an `astring` (RFC 5258 Section 6), and RFC 5258's own
/// examples quote it, so a quoted and a bare tag are both read, as are a
/// quoted and a bare option name inside `CHILDINFO`.
pub(crate) fn mbox_list_extended_item(input: &[u8]) -> IMAPResult<&[u8], ListExtendedItem> {
    let quotable = |name: &'static [u8]| {
        alt((
            delimited(dquote, tag_no_case(name), dquote),
            tag_no_case(name),
        ))
    };
    let option = alt((delimited(dquote, list_select_opt, dquote), list_select_opt));
    alt((
        map(
            preceded(
                tuple((quotable(b"CHILDINFO"), sp)),
                delimited(tag(b"("), separated_list1(sp, option), tag(b")")),
            ),
            |options| ListExtendedItem::ChildInfo(Vec1::unvalidated(options)),
        ),
        map(
            preceded(
                tuple((quotable(b"OLDNAME"), sp)),
                delimited(tag(b"("), mailbox, tag(b")")),
            ),
            ListExtendedItem::OldName,
        ),
    ))(input)
}

/// `mailbox = "INBOX" / astring`
///
/// INBOX is case-insensitive. All case variants of INBOX (e.g., "iNbOx")
/// MUST be interpreted as INBOX not as an astring.
///
/// An astring which consists of the case-insensitive sequence
/// "I" "N" "B" "O" "X" is considered to be INBOX and not an astring.
///
/// Refer to section 5.1 for further semantic details of mailbox names.
pub(crate) fn mailbox(input: &[u8]) -> IMAPResult<&[u8], Mailbox> {
    map(astring, Mailbox::from)(input)
}

/// ```abnf
/// mailbox-data = "FLAGS" SP flag-list /
///                "LIST" SP mailbox-list /
///                "LSUB" SP mailbox-list /
///                "SEARCH" *(SP nz-number) [SP search-sort-mod-seq] /
///                                         ^^^^^^^^^^^^^^^^^^^^^^^^
///                                         |
///                                         RFC 7162 (edited)
///                esearch-response /                       ; RFC 4731
///                "STATUS" SP mailbox SP "(" [status-att-list] ")" /
///                "METADATA" SP mailbox SP (entry-values / entry-list) / ; RFC 5464
///                number SP "EXISTS" /
///                number SP "RECENT"
/// ```
///
/// FROM RFC 7162 (CONDSTORE/QRESYNC):
///
/// ```abnf
/// mailbox-data =/ "SEARCH" [1*(SP nz-number) SP search-sort-mod-seq]
///
/// search-sort-mod-seq = "(" "MODSEQ" SP mod-sequence-value ")"
/// ```
pub(crate) fn mailbox_data(input: &[u8]) -> IMAPResult<&[u8], Data> {
    alt((
        map(preceded(tag_no_case(b"FLAGS "), flag_list), Data::Flags),
        map(
            preceded(
                tag_no_case(b"LIST "),
                tuple((mailbox_list, opt(preceded(sp, mbox_list_extended)))),
            ),
            |((items, delimiter, mailbox), extended)| Data::List {
                items: items.unwrap_or_default(),
                mailbox,
                delimiter,
                extended: extended.unwrap_or_default(),
            },
        ),
        map(
            preceded(tag_no_case(b"LSUB "), mailbox_list),
            |(items, delimiter, mailbox)| Data::Lsub {
                items: items.unwrap_or_default(),
                mailbox,
                delimiter,
            },
        ),
        #[cfg(not(feature = "ext_condstore_qresync"))]
        map(
            #[cfg(not(feature = "quirk_trailing_space_search"))]
            tuple((tag_no_case(b"SEARCH"), many0(preceded(sp, nz_number)))),
            #[cfg(feature = "quirk_trailing_space_search")]
            tuple((
                tag_no_case(b"SEARCH"),
                many0(preceded(sp, nz_number)),
                opt(sp),
            )),
            #[cfg(not(feature = "quirk_trailing_space_search"))]
            |(_, nums)| Data::Search(nums),
            #[cfg(feature = "quirk_trailing_space_search")]
            |(_, nums, _)| Data::Search(nums),
        ),
        #[cfg(feature = "ext_condstore_qresync")]
        map(
            #[cfg(not(feature = "quirk_trailing_space_search"))]
            tuple((
                tag_no_case(b"SEARCH"),
                many0(preceded(sp, nz_number)),
                opt(preceded(char(' '), search_sort_mod_seq)),
            )),
            #[cfg(feature = "quirk_trailing_space_search")]
            tuple((
                tag_no_case(b"SEARCH"),
                many0(preceded(sp, nz_number)),
                opt(preceded(char(' '), search_sort_mod_seq)),
                opt(sp),
            )),
            #[cfg(not(feature = "quirk_trailing_space_search"))]
            |(_, nums, modseq)| Data::Search(nums, modseq),
            #[cfg(feature = "quirk_trailing_space_search")]
            |(_, nums, modseq, _)| Data::Search(nums, modseq),
        ),
        #[cfg(not(feature = "ext_condstore_qresync"))]
        map(
            preceded(tag_no_case(b"SORT"), many0(preceded(sp, nz_number))),
            Data::Sort,
        ),
        #[cfg(feature = "ext_condstore_qresync")]
        map(
            tuple((
                tag_no_case(b"SORT"),
                many0(preceded(sp, nz_number)),
                opt(preceded(char(' '), search_sort_mod_seq)),
            )),
            |(_, nums, modseq)| Data::Sort(nums, modseq),
        ),
        // RFC 4731 Section 3.2 adds `esearch-response` to `mailbox-data`.
        // It has to come before the `SEARCH` arm only in spirit — the two
        // names differ — but it sits here because it answers the same
        // command.
        esearch_response,
        thread_data,
        map(
            tuple((
                tag_no_case(b"STATUS "),
                mailbox,
                delimited(tag(b" ("), opt(status_att_list), tag(b")")),
                #[cfg(feature = "quirk_trailing_space_status")]
                opt(sp),
                #[cfg(not(feature = "quirk_trailing_space_status"))]
                nom::combinator::success(()),
            )),
            |(_, mailbox, items, _)| Data::Status {
                mailbox,
                items: items.unwrap_or_default().into(),
            },
        ),
        #[cfg(feature = "ext_metadata")]
        metadata_resp,
        #[cfg(feature = "ext_namespace")]
        namespace_response,
        map(terminated(number, tag_no_case(b" EXISTS")), Data::Exists),
        map(terminated(number, tag_no_case(b" RECENT")), Data::Recent),
        quotaroot_response,
        quota_response,
    ))(input)
}

/// `mailbox-list = "(" [mbx-list-flags] ")" SP
///                 (DQUOTE QUOTED-CHAR DQUOTE / nil) SP
///                 mailbox`
///
/// RFC 5258 Section 6 appends `[SP mbox-list-extended]`, which is read by
/// the caller for `LIST` and not for `LSUB`, where it has no meaning.
#[allow(clippy::type_complexity)]
pub(crate) fn mailbox_list(
    input: &[u8],
) -> IMAPResult<&[u8], (Option<Vec<FlagNameAttribute>>, Option<QuotedChar>, Mailbox)> {
    let mut parser = tuple((
        delimited(tag(b"("), opt(mbx_list_flags), tag(b")")),
        sp,
        alt((
            map(delimited(dquote, quoted_char, dquote), Option::Some),
            value(None, nil),
        )),
        sp,
        mailbox,
    ));

    let (remaining, (mbx_list_flags, _, maybe_delimiter, _, mailbox)) = parser(input)?;

    Ok((remaining, (mbx_list_flags, maybe_delimiter, mailbox)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use imap_types::{command::CommandBody, response::Response, status::StatusDataItemName};

    use crate::{
        CommandCodec, ResponseCodec,
        decode::Decoder,
        encode::{EncodeContext, EncodeIntoContext},
    };

    fn command(bytes: &[u8]) -> Option<CommandBody<'_>> {
        CommandCodec::default()
            .decode(bytes)
            .ok()
            .map(|(_, command)| command.body)
    }

    fn encoded(item: impl EncodeIntoContext) -> Vec<u8> {
        let mut ctx = EncodeContext::new();
        item.encode_ctx(&mut ctx).unwrap();
        ctx.dump()
    }

    /// RFC 5258 Section 5's examples, each read and written back as it was.
    #[test]
    fn test_list_extended_commands_read_and_write_back() {
        for line in [
            &b"A01 LIST (SUBSCRIBED) \"\" \"*\" RETURN (CHILDREN)\r\n"[..],
            b"A02 LIST (SUBSCRIBED RECURSIVEMATCH) \"\" \"%\"\r\n",
            b"A03 LIST \"\" (\"foo\" \"bar/%\") RETURN (SUBSCRIBED CHILDREN)\r\n",
            b"A04 LIST (REMOTE) \"\" %\r\n",
            b"A05 LIST () \"\" %\r\n",
            b"A06 LIST \"\" % RETURN ()\r\n",
            b"A07 LIST \"\" % RETURN (STATUS (MESSAGES UNSEEN))\r\n",
            b"A08 LIST (SPECIAL-USE) \"\" * RETURN (SPECIAL-USE)\r\n",
            b"A09 LIST \"\" %\r\n",
        ] {
            let (_, parsed) = CommandCodec::default().decode(line).unwrap();
            assert_eq!(encoded(parsed), line, "{}", String::from_utf8_lossy(line));
        }
    }

    #[test]
    fn test_list_extended_command_shapes() {
        let Some(CommandBody::List {
            selection_options,
            patterns,
            return_options,
            ..
        }) = command(b"A LIST (remote subscribed) \"\" (foo \"bar\") return (status (messages size) children)\r\n")
        else {
            panic!("not a LIST");
        };
        assert_eq!(
            selection_options,
            Some(vec![ListSelectOption::Remote, ListSelectOption::Subscribed]),
            "any order, any case"
        );
        assert_eq!(patterns.as_slice().len(), 2);
        assert!(matches!(patterns, ListPatterns::Several(_)));
        assert_eq!(
            return_options,
            Some(vec![
                ListReturnOption::Status(Vec1::unvalidated(vec![
                    StatusDataItemName::Messages,
                    StatusDataItemName::Size,
                ])),
                ListReturnOption::Children,
            ])
        );

        // One pattern in parentheses is extended, and not the bare pattern.
        let Some(CommandBody::List { patterns, .. }) = command(b"A LIST \"\" (\"\")\r\n") else {
            panic!("not a LIST");
        };
        assert!(matches!(patterns, ListPatterns::Several(_)));
        let Some(CommandBody::List {
            selection_options,
            patterns,
            return_options,
            ..
        }) = command(b"A LIST \"\" \"\"\r\n")
        else {
            panic!("not a LIST");
        };
        assert!(matches!(patterns, ListPatterns::One(_)));
        assert_eq!((selection_options, return_options), (None, None));
    }

    /// RFC 5258 Section 3: an option the server does not know, and a
    /// modifier with nothing to modify, are `BAD` — which a command that
    /// does not parse is.
    #[test]
    fn test_list_extended_refusals() {
        for line in [
            &b"A LIST (IMAPTEST) \"\" \"\"\r\n"[..],
            b"A LIST (RECURSIVEMATCH) \"\" \"\"\r\n",
            b"A LIST (RECURSIVEMATCH REMOTE) \"\" \"\"\r\n",
            b"A LIST \"\" \"\" RETURN (IMAPTEST)\r\n",
            b"A LIST \"\" ()\r\n",
            b"A LIST \"\" % RETURN (STATUS ())\r\n",
        ] {
            assert!(
                command(line).is_none(),
                "{} should not parse",
                String::from_utf8_lossy(line)
            );
        }
    }

    #[test]
    fn test_list_extended_responses() {
        let childinfo: &[u8] = b"* LIST () \"/\" \"Foo\" (\"CHILDINFO\" (\"SUBSCRIBED\"))\r\n";
        let (_, response) = ResponseCodec::default().decode(childinfo).unwrap();
        let Response::Data(Data::List { extended, .. }) = &response else {
            panic!("not a LIST response");
        };
        assert_eq!(
            extended,
            &vec![ListExtendedItem::ChildInfo(Vec1::from(
                ListSelectOption::Subscribed
            ))]
        );
        assert_eq!(
            encoded(response),
            childinfo,
            "written as RFC 5258 writes it"
        );

        // Unquoted and in lower case, as Dovecot's ImapTest spells it.
        let (_, bare) = ResponseCodec::default()
            .decode(b"* LIST () \"/\" Foo (childinfo (subscribed))\r\n")
            .unwrap();
        assert!(
            matches!(bare, Response::Data(Data::List { ref extended, .. }) if extended.len() == 1)
        );

        let oldname: &[u8] = b"* LIST () \"/\" \"New\" (\"OLDNAME\" (\"Old\"))\r\n";
        let (_, response) = ResponseCodec::default().decode(oldname).unwrap();
        assert_eq!(encoded(response), oldname);

        // No extended data is no extended data, and is written as none.
        let plain: &[u8] = b"* LIST (\\HasNoChildren) \"/\" \"Foo\"\r\n";
        let (_, response) = ResponseCodec::default().decode(plain).unwrap();
        assert_eq!(encoded(response), plain);
    }

    #[test]
    fn test_mailbox() {
        assert!(mailbox(b"\"iNbOx\"").is_ok());
        assert!(mailbox(b"{3}\r\naaa\r\n").is_ok());
        assert!(mailbox(b"inbox ").is_ok());
        assert!(mailbox(b"inbox.sent ").is_ok());
        assert!(mailbox(b"aaa").is_err());
    }
}
