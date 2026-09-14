//! NOTIFY (RFC 5465).

use std::io::Write;

use abnf_core::streaming::sp;
use imap_types::{
    command::CommandBody,
    core::Vec1,
    extensions::notify::{Event, EventGroup, FilterMailboxes, NotifySet},
    response::Code,
};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::{map, opt, value},
    multi::separated_list1,
    sequence::{delimited, preceded, tuple},
};

use crate::{
    core::atom,
    decode::IMAPResult,
    encode::{EncodeContext, EncodeIntoContext},
    fetch::fetch_att,
    mailbox::mailbox,
};

/// ```abnf
/// notify       = "NOTIFY" SP (notify-set / notify-none)
/// notify-set   = "SET" [status-indicator] SP event-groups
/// notify-none  = "NONE"
/// status-indicator = SP "STATUS"
/// event-groups = event-group *(SP event-group)
/// ```
pub(crate) fn notify(input: &[u8]) -> IMAPResult<&[u8], CommandBody> {
    preceded(
        tag_no_case(b"NOTIFY "),
        alt((
            value(CommandBody::Notify { set: None }, tag_no_case(b"NONE")),
            map(
                tuple((
                    tag_no_case(b"SET"),
                    opt(tag_no_case(b" STATUS")),
                    sp,
                    separated_list1(sp, event_group),
                )),
                |(_, status, _, groups)| CommandBody::Notify {
                    set: Some(NotifySet {
                        status: status.is_some(),
                        groups: Vec1::unvalidated(groups),
                    }),
                },
            ),
        )),
    )(input)
}

/// `event-group = "(" filter-mailboxes SP events ")"`
fn event_group(input: &[u8]) -> IMAPResult<&[u8], EventGroup> {
    map(
        delimited(tag(b"("), tuple((filter_mailboxes, sp, events)), tag(b")")),
        |(mailboxes, _, events)| EventGroup { mailboxes, events },
    )(input)
}

/// ```abnf
/// filter-mailboxes-selected = "selected" / "selected-delayed"
/// filter-mailboxes-other    = "inboxes" / "personal" / "subscribed" /
///                             ( "subtree" SP one-or-more-mailbox ) /
///                             ( "mailboxes" SP one-or-more-mailbox )
/// ```
fn filter_mailboxes(input: &[u8]) -> IMAPResult<&[u8], FilterMailboxes> {
    alt((
        // Before `selected`, which is a prefix of it.
        value(
            FilterMailboxes::SelectedDelayed,
            tag_no_case(b"selected-delayed"),
        ),
        value(FilterMailboxes::Selected, tag_no_case(b"selected")),
        value(FilterMailboxes::Inboxes, tag_no_case(b"inboxes")),
        value(FilterMailboxes::Personal, tag_no_case(b"personal")),
        value(FilterMailboxes::Subscribed, tag_no_case(b"subscribed")),
        map(
            preceded(tag_no_case(b"subtree "), one_or_more_mailbox),
            FilterMailboxes::Subtree,
        ),
        map(
            preceded(tag_no_case(b"mailboxes "), one_or_more_mailbox),
            FilterMailboxes::Mailboxes,
        ),
    ))(input)
}

/// ```abnf
/// one-or-more-mailbox = mailbox / many-mailboxes
/// many-mailboxes      = "(" mailbox *(SP mailbox) ")"
/// ```
fn one_or_more_mailbox(input: &[u8]) -> IMAPResult<&[u8], Vec1<imap_types::mailbox::Mailbox>> {
    alt((
        map(
            delimited(tag(b"("), separated_list1(sp, mailbox), tag(b")")),
            Vec1::unvalidated,
        ),
        map(mailbox, Vec1::from),
    ))(input)
}

/// `events = ( "(" event *(SP event) ")" ) / "NONE"`
fn events(input: &[u8]) -> IMAPResult<&[u8], Option<Vec1<Event>>> {
    alt((
        value(None, tag_no_case(b"NONE")),
        map(
            delimited(tag(b"("), separated_list1(sp, event), tag(b")")),
            |events| Some(Vec1::unvalidated(events)),
        ),
    ))(input)
}

/// ```abnf
/// message-event = ( "MessageNew" [SP "(" fetch-att *(SP fetch-att) ")" ] ) /
///                 "MessageExpunge" / "FlagChange" / "AnnotationChange"
/// mailbox-event = "MailboxName" / "SubscriptionChange" / "MailboxMetadataChange"
/// user-event    = "ServerMetadataChange"
/// event-ext     = atom
/// ```
fn event(input: &[u8]) -> IMAPResult<&[u8], Event> {
    alt((
        map(
            preceded(
                tag_no_case(b"MessageNew"),
                opt(preceded(
                    sp,
                    delimited(tag(b"("), separated_list1(sp, fetch_att), tag(b")")),
                )),
            ),
            |attributes| Event::MessageNew(attributes.unwrap_or_default()),
        ),
        value(Event::MessageExpunge, tag_no_case(b"MessageExpunge")),
        value(Event::FlagChange, tag_no_case(b"FlagChange")),
        value(Event::AnnotationChange, tag_no_case(b"AnnotationChange")),
        value(Event::MailboxName, tag_no_case(b"MailboxName")),
        value(
            Event::SubscriptionChange,
            tag_no_case(b"SubscriptionChange"),
        ),
        value(
            Event::MailboxMetadataChange,
            tag_no_case(b"MailboxMetadataChange"),
        ),
        value(
            Event::ServerMetadataChange,
            tag_no_case(b"ServerMetadataChange"),
        ),
        map(atom, Event::Other),
    ))(input)
}

/// ```abnf
/// resp-text-code =/ "NOTIFICATIONOVERFLOW" / unsupported-events-code
/// unsupported-events-code = "BADEVENT" SP "(" event-name *(SP event-name) ")"
/// ```
pub(crate) fn resp_code_notify(input: &[u8]) -> IMAPResult<&[u8], Code> {
    alt((
        value(
            Code::NotificationOverflow,
            tag_no_case(b"NOTIFICATIONOVERFLOW"),
        ),
        map(
            preceded(
                tag_no_case(b"BADEVENT ("),
                tuple((separated_list1(sp, atom), tag(b")"))),
            ),
            |(names, _)| Code::BadEvent(Vec1::unvalidated(names)),
        ),
    ))(input)
}

impl EncodeIntoContext for NotifySet<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        ctx.write_all(b"SET")?;
        if self.status {
            ctx.write_all(b" STATUS")?;
        }
        for group in self.groups.as_ref() {
            ctx.write_all(b" ")?;
            group.encode_ctx(ctx)?;
        }
        Ok(())
    }
}

impl EncodeIntoContext for EventGroup<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        ctx.write_all(b"(")?;
        let many = |ctx: &mut EncodeContext, mailboxes: &Vec1<imap_types::mailbox::Mailbox>| {
            match mailboxes.as_ref() {
                [one] => one.encode_ctx(ctx),
                all => {
                    ctx.write_all(b"(")?;
                    for (i, mailbox) in all.iter().enumerate() {
                        if i > 0 {
                            ctx.write_all(b" ")?;
                        }
                        mailbox.encode_ctx(ctx)?;
                    }
                    ctx.write_all(b")")
                }
            }
        };
        match &self.mailboxes {
            FilterMailboxes::Selected => ctx.write_all(b"selected")?,
            FilterMailboxes::SelectedDelayed => ctx.write_all(b"selected-delayed")?,
            FilterMailboxes::Inboxes => ctx.write_all(b"inboxes")?,
            FilterMailboxes::Personal => ctx.write_all(b"personal")?,
            FilterMailboxes::Subscribed => ctx.write_all(b"subscribed")?,
            FilterMailboxes::Subtree(mailboxes) => {
                ctx.write_all(b"subtree ")?;
                many(ctx, mailboxes)?;
            }
            FilterMailboxes::Mailboxes(mailboxes) => {
                ctx.write_all(b"mailboxes ")?;
                many(ctx, mailboxes)?;
            }
        }
        ctx.write_all(b" ")?;
        match &self.events {
            None => ctx.write_all(b"NONE")?,
            Some(events) => {
                ctx.write_all(b"(")?;
                for (i, event) in events.as_ref().iter().enumerate() {
                    if i > 0 {
                        ctx.write_all(b" ")?;
                    }
                    event.encode_ctx(ctx)?;
                }
                ctx.write_all(b")")?;
            }
        }
        ctx.write_all(b")")
    }
}

impl EncodeIntoContext for Event<'_> {
    fn encode_ctx(&self, ctx: &mut EncodeContext) -> std::io::Result<()> {
        match self {
            Event::MessageNew(attributes) => {
                ctx.write_all(b"MessageNew")?;
                if let Some((first, rest)) = attributes.split_first() {
                    ctx.write_all(b" (")?;
                    first.encode_ctx(ctx)?;
                    for attribute in rest {
                        ctx.write_all(b" ")?;
                        attribute.encode_ctx(ctx)?;
                    }
                    ctx.write_all(b")")?;
                }
                Ok(())
            }
            Event::MessageExpunge => ctx.write_all(b"MessageExpunge"),
            Event::FlagChange => ctx.write_all(b"FlagChange"),
            Event::AnnotationChange => ctx.write_all(b"AnnotationChange"),
            Event::MailboxName => ctx.write_all(b"MailboxName"),
            Event::SubscriptionChange => ctx.write_all(b"SubscriptionChange"),
            Event::MailboxMetadataChange => ctx.write_all(b"MailboxMetadataChange"),
            Event::ServerMetadataChange => ctx.write_all(b"ServerMetadataChange"),
            Event::Other(name) => name.encode_ctx(ctx),
        }
    }
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

    /// RFC 5465's examples and ImapTest's, read and written back.
    #[test]
    fn test_notify_round_trips() {
        let body = round_trip_command(b"a NOTIFY NONE\r\n");
        assert!(matches!(body, CommandBody::Notify { set: None }));
        round_trip_command(
            b"b NOTIFY SET (selected (MessageNew (UID BODY.PEEK[HEADER.FIELDS (From To)]) MessageExpunge)) (subtree Lists (MessageNew MessageExpunge))\r\n",
        );
        round_trip_command(
            b"c NOTIFY SET STATUS (selected (MessageNew (UID) MessageExpunge FlagChange)) (mailboxes (INBOX Drafts) (MessageNew MessageExpunge))\r\n",
        );
        round_trip_command(b"d NOTIFY SET (personal (MailboxName SubscriptionChange MailboxMetadataChange ServerMetadataChange))\r\n");
        round_trip_command(b"e NOTIFY SET (selected-delayed (MessageNew MessageExpunge FlagChange AnnotationChange)) (inboxes NONE) (subscribed (MessageNew MessageExpunge XFutureEvent))\r\n");
        round_trip_command(
            b"f NOTIFY SET STATUS (mailboxes imaptest2 (MessageNew MessageExpunge FlagChange))\r\n",
        );

        round_trip_response(b"g NO [BADEVENT (MessageNew MessageExpunge FlagChange MailboxName SubscriptionChange)] Unsupported event\r\n");
        round_trip_response(b"* OK [NOTIFICATIONOVERFLOW] Too many\r\n");
        round_trip_response(b"* CAPABILITY IMAP4REV1 NOTIFY\r\n");
    }

    #[test]
    fn test_notify_refusals() {
        for line in [
            &b"a NOTIFY\r\n"[..],
            b"a NOTIFY SET\r\n",
            b"a NOTIFY SET (selected)\r\n",
            b"a NOTIFY SET (mailboxes (MessageNew))\r\n",
            b"a NOTIFY SET (elsewhere (MessageNew MessageExpunge))\r\n",
            b"a NOTIFY SET (selected ())\r\n",
        ] {
            assert!(
                CommandCodec::default().decode(line).is_err(),
                "{} should not parse",
                String::from_utf8_lossy(line)
            );
        }
    }
}
