use actix_web::HttpRequest;
use actix_web::http::header::{self, HeaderName};
use config::proxying::Proxying;
use services::provenance::Provenance;

/// What this request said about where it came from.
///
/// The proxying is read off the plane rather than taken as an argument, so a
/// handler that wants the answer asks for it and nothing else. Absent, no
/// header is read: that is the peer, which is the one address nobody claimed.
pub fn read_provenance(request: &HttpRequest) -> Provenance {
    let proxying = request
        .app_data::<actix_web::web::Data<Proxying>>()
        .map_or_else(Proxying::none, |held| (***held).clone());
    read_provenance_under(request, &proxying)
}

fn read_provenance_under(request: &HttpRequest, proxying: &Proxying) -> Provenance {
    let peer = request.peer_addr().map(|address| address.ip().to_string());
    let carried = proxying
        .header()
        .and_then(|named| HeaderName::from_bytes(named.name().as_bytes()).ok())
        .and_then(|named| request.headers().get(named))
        .and_then(|value| value.to_str().ok());
    Provenance::seen(
        proxying.caller(peer.as_deref(), carried),
        request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use config::proxying::ProxyHeader;

    #[test]
    fn a_deployment_with_no_proxy_records_the_peer() {
        let request = TestRequest::default()
            .peer_addr("10.0.0.9:5000".parse().unwrap())
            .insert_header((header::X_FORWARDED_FOR, "203.0.113.7"))
            .insert_header((header::USER_AGENT, "Mozilla/5.0"))
            .to_http_request();
        let seen = read_provenance(&request);
        assert_eq!(seen.address.as_deref(), Some("10.0.0.9"));
        assert_eq!(seen.agent.as_deref(), Some("Mozilla/5.0"));
    }

    /// The header a deployment did not name is not read, whatever it carries.
    #[test]
    fn only_the_named_header_is_read() {
        let request = TestRequest::default()
            .peer_addr("10.0.0.9:5000".parse().unwrap())
            .insert_header((header::X_FORWARDED_FOR, "198.51.100.1"))
            .insert_header((header::FORWARDED, "for=203.0.113.7"))
            .to_http_request();

        assert_eq!(
            read_provenance_under(&request, &Proxying::behind(1, ProxyHeader::Forwarded)).address,
            Some("203.0.113.7".to_owned())
        );
        assert_eq!(
            read_provenance_under(&request, &Proxying::behind(1, ProxyHeader::XForwardedFor))
                .address,
            Some("198.51.100.1".to_owned())
        );
    }

    #[test]
    fn nothing_sent_is_nothing_recorded() {
        let request = TestRequest::default().to_http_request();
        assert_eq!(read_provenance(&request), Provenance::default());
    }
}
