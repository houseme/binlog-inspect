// Copyright (c) 2026 houseme
// SPDX-License-Identifier: Apache-2.0

//! Event, table, range and GTID filters applied after parsing.
use crate::event::{EventPayload, EventType, ParsedEvent};
use std::collections::HashSet;
/// Byte-offset and timestamp range filters (mysqlbinlog convention).
///
/// All bounds are optional; filtering happens after parsing, so it never
/// changes parser state.
#[derive(Debug, Default)]
pub struct RangeFilter {
    /// Keep events starting at or after this byte offset (inclusive).
    pub start_position: Option<u64>,
    /// Keep events starting before this byte offset (exclusive).
    pub stop_position: Option<u64>,
    /// Keep events with timestamp at or after this Unix second (inclusive).
    ///
    /// Events with a zero timestamp (heartbeat-style) fall before any real
    /// datetime start bound, which matches mysqlbinlog.
    pub start_datetime: Option<i64>,
    /// Keep events with timestamp at or before this Unix second (inclusive).
    pub stop_datetime: Option<i64>,
}
impl RangeFilter {
    /// Returns whether the event header offset and timestamp are inside the
    /// configured ranges.
    fn keep(&self, event: &ParsedEvent) -> bool {
        if let Some(start) = self.start_position
            && event.offset < start
        {
            return false;
        }
        // mysqlbinlog convention: the stop position is exclusive.
        if let Some(stop) = self.stop_position
            && event.offset >= stop
        {
            return false;
        }
        let timestamp = i64::from(event.timestamp);
        if let Some(start) = self.start_datetime
            && timestamp < start
        {
            return false;
        }
        if let Some(stop) = self.stop_datetime
            && timestamp > stop
        {
            return false;
        }
        true
    }
}
/// Optional allow lists for event types and fully qualified tables, plus
/// range bounds and an exact-match GTID allow list.
#[derive(Default)]
pub struct EventFilter {
    /// Empty means all event types.
    pub kinds: HashSet<EventType>,
    /// Empty means all tables; non-table events are excluded when set.
    ///
    /// Entries are `(database, table)` pairs; the CLI splits `--table`
    /// values at the first `.` at parse time (R16).
    pub tables: HashSet<(String, String)>,
    /// Byte-offset and timestamp range bounds (R26).
    pub ranges: RangeFilter,
    /// Empty means all GTIDs; when set, only events carrying one of these
    /// exact GTID strings are kept (R26).
    ///
    /// Entries are canonical `uuid:gno` or `uuid:tag:gno` strings exactly as
    /// they appear in [`ParsedEvent`] output; no interval or set algebra.
    pub gtids: HashSet<String>,
}
impl EventFilter {
    /// Returns whether the event matches all configured filters.
    ///
    /// Table matching is a scan over the `(database, table)` tuple set with no
    /// per-event allocation; filter lists are small, so the scan is cheaper
    /// than the string formatting it replaced.
    pub fn keep(&self, event: &ParsedEvent) -> bool {
        if !self.kinds.is_empty() && !self.kinds.contains(&event.event_type) {
            return false;
        }
        if !self.ranges.keep(event) {
            return false;
        }
        if !self.gtids.is_empty() {
            match &event.payload {
                EventPayload::Gtid { gtid, .. } if self.gtids.contains(gtid) => (),
                // A GTID allow list only matches GTID payload events; every
                // other event (and anonymous transactions, whose GTID is the
                // placeholder "ANONYMOUS") is excluded.
                _ => return false,
            }
        }
        if self.tables.is_empty() {
            return true;
        }
        match &event.payload {
            EventPayload::Rows {
                database, table, ..
            }
            | EventPayload::PartialUpdateRows {
                database, table, ..
            }
            | EventPayload::TableMap {
                database, table, ..
            } => self
                .tables
                .iter()
                .any(|(db, tbl)| db == database && tbl == table),
            // Row events without a usable table map carry no table identity,
            // so they never match a table filter.
            _ => false,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn xid(offset: u64, timestamp: u32) -> ParsedEvent {
        ParsedEvent {
            offset,
            timestamp,
            event_type: EventType::Xid,
            event_type_code: 16,
            server_id: 1,
            event_size: 27,
            log_pos: u32::try_from(offset + 27).unwrap(),
            payload: EventPayload::Xid { xid: 1 },
        }
    }
    fn gtid(offset: u64, gtid: &str) -> ParsedEvent {
        ParsedEvent {
            offset,
            timestamp: 1,
            event_type: EventType::Gtid,
            event_type_code: 33,
            server_id: 1,
            event_size: 42,
            log_pos: u32::try_from(offset + 42).unwrap(),
            payload: EventPayload::Gtid {
                gtid: gtid.to_owned(),
                tag: None,
            },
        }
    }
    #[test]
    fn position_bounds_are_start_inclusive_and_stop_exclusive() {
        let filter = EventFilter {
            ranges: RangeFilter {
                start_position: Some(4),
                stop_position: Some(31),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(filter.keep(&xid(4, 1)));
        // Before the exclusive stop bound: kept.
        assert!(filter.keep(&xid(30, 1)));
        // At the exclusive stop bound: dropped.
        assert!(!filter.keep(&xid(31, 1)));
    }
    #[test]
    fn datetime_bounds_are_inclusive_on_both_ends() {
        let filter = EventFilter {
            ranges: RangeFilter {
                start_datetime: Some(100),
                stop_datetime: Some(200),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(filter.keep(&xid(4, 100)));
        assert!(filter.keep(&xid(4, 200)));
        assert!(!filter.keep(&xid(4, 99)));
        assert!(!filter.keep(&xid(4, 201)));
        // A zero timestamp never satisfies a real datetime start bound.
        assert!(!filter.keep(&xid(4, 0)));
    }
    #[test]
    fn gtid_allow_list_matches_exact_strings_only() {
        let filter = EventFilter {
            gtids: ["11111111-1111-1111-1111-111111111111:1".to_owned()]
                .into_iter()
                .collect(),
            ..Default::default()
        };
        assert!(filter.keep(&gtid(4, "11111111-1111-1111-1111-111111111111:1")));
        assert!(!filter.keep(&gtid(4, "11111111-1111-1111-1111-111111111111:2")));
        assert!(!filter.keep(&gtid(4, "ANONYMOUS")));
        assert!(!filter.keep(&xid(4, 1)));
    }
}
