use super::{BackendLocale, APP_NAME};

pub struct EnglishLocale;

impl BackendLocale for EnglishLocale {
    fn oauth_success_html(&self) -> &'static str {
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n\
         <html lang=\"en\"><body><h1>Authorization successful</h1>\
         <p>OpenAI connected successfully. You can close this window and return to the app.</p>\
         <script>setTimeout(() => window.close(), 3000)</script></body></html>"
    }

    fn oauth_failure_response(&self) -> &'static str {
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Authorization failed: state validation failed or required parameters are missing"
    }

    fn tray_tooltip_logged_out(&self) -> String {
        format!("{APP_NAME} - signed out")
    }

    fn tray_tooltip_account(&self, name: &str, five_hour_left: f64, weekly_left: f64) -> String {
        format!("{APP_NAME} - {name} | 5H: {five_hour_left:.0}%  weekly: {weekly_left:.0}%")
    }

    fn tray_show_main(&self) -> &'static str {
        "Open Main Window"
    }

    fn tray_next_account(&self) -> &'static str {
        "Switch to Next Account"
    }

    fn tray_quit(&self) -> &'static str {
        "Quit"
    }

    fn notification_account_banned_subtitle(&self) -> &'static str {
        "Account Banned"
    }

    fn notification_auto_switch_subtitle(&self) -> &'static str {
        "Automatic Switch"
    }

    fn injected_switch_message(&self, account_name: &str) -> String {
        format!("⚡ [Codex Switcher] Switched to {account_name}")
    }

    fn referral_unsupported_program(&self) -> &'static str {
        "Unsupported referral campaign type"
    }

    fn referral_uncertain_send_suffix(&self) -> &'static str {
        "; send result is unconfirmed. Check invitation history before retrying"
    }

    fn referral_network_error(&self, error: &reqwest::Error, uncertain: &str) -> String {
        format!("Referral API network error: {error}{uncertain}")
    }

    fn referral_non_json_response(&self, status: u16, uncertain: &str) -> String {
        format!(
            "Referral API returned a non-JSON HTTP {status} response. The official desktop login session may be required; campaign eligibility could not be confirmed{uncertain}"
        )
    }

    fn referral_upstream_rejected(&self) -> &'static str {
        "Upstream rejected the request"
    }

    fn referral_failed_emails(&self, emails: &serde_json::Value) -> String {
        format!("; email: {emails}")
    }

    fn referral_unrecognized_response(&self, uncertain: &str) -> String {
        format!("Could not recognize referral API response{uncertain}")
    }

    fn referral_missing_items(&self) -> &'static str {
        "Invitation-history response is missing items; records could not be confirmed"
    }

    fn referral_no_available_campaign(&self) -> &'static str {
        "No referral campaign is available for the current account; refresh eligibility"
    }
}
