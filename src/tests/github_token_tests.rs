#[cfg(test)]
mod tests {
    use crate::init::setup::{classify_github_status, is_github_token_format, TokenCheck};

    /// Test a fine-grained personal access token is the right format
    #[test]
    fn test_is_github_token_format_fine_grained() {
        assert!(is_github_token_format("github_pat_11ABCDEFG0abcdefghijklmnop"));
    }

    /// Test a missing token is not the right format
    #[test]
    fn test_is_github_token_format_empty() {
        assert!(!is_github_token_format(""));
    }

    /// Test a classic personal access token is not accepted, as setup needs a fine-grained one
    #[test]
    fn test_is_github_token_format_classic() {
        assert!(!is_github_token_format("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));
    }

    /// Test a token with the prefix somewhere other than the start is not the right format
    #[test]
    fn test_is_github_token_format_prefix_not_at_start() {
        assert!(!is_github_token_format("not_a_token"));
        assert!(!is_github_token_format(" github_pat_11ABCDEFG0abcdefghijklmnop"));
    }

    /// Test the GitHub API accepting the token is a valid token
    #[test]
    fn test_classify_github_status_ok() {
        assert_eq!(classify_github_status(200), TokenCheck::Valid);
    }

    /// Test bad credentials, i.e. an expired or revoked token, is an invalid token
    #[test]
    fn test_classify_github_status_unauthorised() {
        match classify_github_status(401) {
            TokenCheck::Invalid(msg) => assert!(msg.contains("bad credentials")),
            other => panic!("expected the token to be invalid, got: {:?}", other),
        }
    }

    /// Test being rate limited doesn't mark the token as invalid, as the token may be fine
    #[test]
    fn test_classify_github_status_rate_limited() {
        for code in [403, 429] {
            match classify_github_status(code) {
                TokenCheck::Unknown(msg) => assert!(msg.contains("rate limited")),
                other => panic!("expected the check to be unknown, got: {:?}", other),
            }
        }
    }

    /// Test any other status leaves the check unknown
    #[test]
    fn test_classify_github_status_other() {
        for code in [404, 500, 502] {
            match classify_github_status(code) {
                TokenCheck::Unknown(msg) => assert!(msg.contains(&code.to_string())),
                other => panic!("expected the check to be unknown, got: {:?}", other),
            }
        }
    }
}
