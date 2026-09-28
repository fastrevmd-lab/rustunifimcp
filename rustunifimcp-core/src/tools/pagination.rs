//! Shared local pagination.
//!
//! `unifi_query_stats` and the workflow reports read from the Private v1
//! surface or join several surfaces together, and in both cases there is no
//! upstream page to defer to: the private stats endpoints return their whole
//! collection regardless of what `offset`/`limit` ask for (see
//! `apply_page_if_upstream_ignored_it` in `tools/read.rs` for the same fact
//! about the private *resource* endpoints), and a join has no upstream call
//! at all. So these tools page the result themselves, once, after the data is
//! in hand.

use crate::error::UnifiError;

/// Items per page when a caller does not name a limit.
pub(crate) const DEFAULT_PAGE_SIZE: u32 = 200;

/// A page of items, together with the total it was cut from.
pub(crate) struct Paged {
    /// The items in this page.
    pub items: Vec<serde_json::Value>,
    /// The offset this page starts at.
    pub offset: u64,
    /// The page size actually applied.
    pub limit: u32,
    /// The size of the collection `items` was cut from.
    pub total: usize,
}

/// Validate `offset`/`limit` and slice `items` to the requested window.
///
/// # Errors
///
/// Returns [`UnifiError::Malformed`] if `offset`/`limit` fail
/// [`mecmcp_openapi::page`]'s validation -- a zero limit, or an offset/limit
/// past the configured maximum.
pub(crate) fn paginate(
    items: Vec<serde_json::Value>,
    offset: Option<u64>,
    limit: Option<u32>,
) -> Result<Paged, UnifiError> {
    let total = items.len();
    let page = mecmcp_openapi::page(
        offset.unwrap_or(0),
        u64::from(limit.unwrap_or(DEFAULT_PAGE_SIZE)),
        mecmcp_openapi::PageLimits::default(),
    )
    .map_err(|error| UnifiError::Malformed(error.to_string()))?;

    let from = usize::try_from(page.from).unwrap_or(usize::MAX);
    let size = usize::try_from(page.size).unwrap_or(usize::MAX);
    let windowed = items.into_iter().skip(from).take(size).collect();

    Ok(Paged {
        items: windowed,
        offset: u64::from(page.from),
        limit: page.size,
        total,
    })
}

#[cfg(test)]
mod tests {
    use super::paginate;

    fn array(n: usize) -> Vec<serde_json::Value> {
        (0..n).map(|i| serde_json::json!({ "n": i })).collect()
    }

    #[test]
    fn a_page_carries_the_window_it_was_cut_from() {
        let paged = paginate(array(10), Some(2), Some(3)).expect("valid page");
        assert_eq!(paged.items.len(), 3);
        assert_eq!(paged.offset, 2);
        assert_eq!(paged.limit, 3);
        assert_eq!(paged.total, 10);
        assert_eq!(paged.items[0]["n"], 2);
    }

    #[test]
    fn defaults_to_a_full_first_page() {
        let paged = paginate(array(5), None, None).expect("valid page");
        assert_eq!(paged.items.len(), 5);
        assert_eq!(paged.offset, 0);
    }

    #[test]
    fn an_offset_past_the_collection_yields_an_empty_page_not_an_error() {
        let paged = paginate(array(5), Some(100), None).expect("valid page");
        assert!(paged.items.is_empty());
        assert_eq!(paged.total, 5);
    }

    #[test]
    fn zero_limit_is_refused() {
        assert!(paginate(array(5), None, Some(0)).is_err());
    }
}
