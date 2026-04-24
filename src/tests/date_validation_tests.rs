#[cfg(test)]
mod tests {
    use crate::ops::file_ops;

    /// Test check_date with valid YYYY-MM-DD format
    #[test]
    fn test_check_date_valid_yyyy_mm_dd() {
        let date = "2023-12-25".to_string();
        let date_type = "test date".to_string();

        let result = file_ops::check_date(date.clone(), &date_type);

        assert_eq!(result, date);
    }

    /// Test check_date with valid YYYY-MM-DD format (different date)
    #[test]
    fn test_check_date_valid_format_2024() {
        let date = "2024-06-15".to_string();
        let date_type = "start date".to_string();

        let result = file_ops::check_date(date.clone(), &date_type);

        assert_eq!(result, date);
    }

    /// Test check_date accepts valid recent date
    #[test]
    fn test_check_date_valid_recent_date() {
        let date = "2025-01-01".to_string();
        let date_type = "end date".to_string();

        let result = file_ops::check_date(date.clone(), &date_type);

        assert_eq!(result, date);
    }

    /// Test check_date accepts valid date in the past
    #[test]
    fn test_check_date_valid_past_date() {
        let date = "2020-03-15".to_string();
        let date_type = "start date".to_string();

        let result = file_ops::check_date(date.clone(), &date_type);

        assert_eq!(result, date);
    }

    /// Test check_date with leap year date
    #[test]
    fn test_check_date_leap_year() {
        let date = "2024-02-29".to_string();
        let date_type = "test date".to_string();

        let result = file_ops::check_date(date.clone(), &date_type);

        assert_eq!(result, date);
    }

    /// Test check_date with end of year date
    #[test]
    fn test_check_date_end_of_year() {
        let date = "2023-12-31".to_string();
        let date_type = "end date".to_string();

        let result = file_ops::check_date(date.clone(), &date_type);

        assert_eq!(result, date);
    }

    /// Test check_date with start of year date
    #[test]
    fn test_check_date_start_of_year() {
        let date = "2023-01-01".to_string();
        let date_type = "start date".to_string();

        let result = file_ops::check_date(date.clone(), &date_type);

        assert_eq!(result, date);
    }

    // Note: Tests for invalid dates that require user prompts should be in integration tests
    // as they need TTY input which is not available in unit tests
}
