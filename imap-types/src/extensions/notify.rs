//! NOTIFY (RFC 5465): which changes a client wants to hear about without
//! asking, in which mailboxes.

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    core::{Atom, Vec1},
    fetch::MessageDataItemName,
    mailbox::Mailbox,
};

/// `notify-set = "SET" [status-indicator] SP event-groups`.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct NotifySet<'a> {
    /// `STATUS`: send each watched mailbox's STATUS before the OK.
    pub status: bool,
    /// The event groups, which replace any registered before.
    pub groups: Vec1<EventGroup<'a>>,
}

/// `event-group = "(" filter-mailboxes SP events ")"`.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct EventGroup<'a> {
    /// Which mailboxes.
    pub mailboxes: FilterMailboxes<'a>,
    /// The events, or `None` for `NONE`: nothing from these mailboxes.
    pub events: Option<Vec1<Event<'a>>>,
}

/// `filter-mailboxes`.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum FilterMailboxes<'a> {
    /// `selected`: the open mailbox, told at once.
    Selected,
    /// `selected-delayed`: the open mailbox, expunges held for a command
    /// that may report them.
    SelectedDelayed,
    /// `inboxes`: every mailbox that receives mail.
    Inboxes,
    /// `personal`: every mailbox in the user's own namespace.
    Personal,
    /// `subscribed`: every subscribed mailbox.
    Subscribed,
    /// `subtree`: these mailboxes and everything under them.
    Subtree(Vec1<Mailbox<'a>>),
    /// `mailboxes`: exactly these, with no wildcard expansion.
    Mailboxes(Vec1<Mailbox<'a>>),
}

/// `event`.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum Event<'a> {
    /// `MessageNew`, with the fetch attributes to send for each new
    /// message in the selected mailbox; empty when none were given.
    MessageNew(Vec<MessageDataItemName<'a>>),
    /// `MessageExpunge`.
    MessageExpunge,
    /// `FlagChange`.
    FlagChange,
    /// `AnnotationChange`.
    AnnotationChange,
    /// `MailboxName`.
    MailboxName,
    /// `SubscriptionChange`.
    SubscriptionChange,
    /// `MailboxMetadataChange`.
    MailboxMetadataChange,
    /// `ServerMetadataChange`.
    ServerMetadataChange,
    /// `event-ext`: a name this crate does not know.
    Other(Atom<'a>),
}
