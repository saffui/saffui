//! What every list of the administration plane reads and answers alike.

use actix_web::HttpResponse;
use actix_web::http::header::WARNING;
use api::Page;
use saffui_core::clients::store::ListWindow;
use saffui_core::error::{ErrorCode, Failure};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ListParameters {
    first: Option<u32>,
    max: Option<u32>,
    count: Option<bool>,
}

impl ListParameters {
    /// The window asked for, bounded, and whether it was cut to the ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::ListOffsetTooLarge`].
    pub(super) fn bound(&self) -> Result<(ListWindow, bool), Failure> {
        ListWindow::bound(self.first, self.max)
            .ok_or_else(|| Failure::new(ErrorCode::ListOffsetTooLarge))
    }

    pub(super) fn is_counted(&self) -> bool {
        self.count.unwrap_or(false)
    }
}

/// A page of a list. A page cut to the ceiling is still an answer: it says
/// it was cut.
pub(super) fn answer_page<T: Serialize>(
    window: ListWindow,
    cut: bool,
    items: Vec<T>,
    total: Option<u64>,
) -> HttpResponse {
    let mut response = HttpResponse::Ok();
    if cut {
        response.insert_header((WARNING, "299 - \"max was lowered to 500\""));
    }
    response.json(Page {
        items,
        first: window.first,
        max: window.max,
        total,
    })
}
