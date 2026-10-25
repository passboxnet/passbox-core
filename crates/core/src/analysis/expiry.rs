//! Expiry dates of cards and documents as people type them.

/// A parsed expiry date: the last day something is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expiry {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    /// Only month and year were given (cards): valid to the end of the month.
    pub month_only: bool,
}

impl Expiry {
    /// `YYYY-MM` or `YYYY-MM-DD`.
    pub fn display(&self) -> String {
        if self.month_only {
            format!("{:04}-{:02}", self.year, self.month)
        } else {
            format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
        }
    }

    /// Days since 1970-01-01 of the last valid day.
    pub fn last_day(&self) -> i64 {
        days_from_civil(self.year, self.month, self.day)
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (proleptic Gregorian calendar).
pub fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = i64::from(year) - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn year_of(text: &str) -> Option<i32> {
    let value: i32 = text.parse().ok()?;
    match text.len() {
        2 => Some(2000 + value),
        4 if (1900..=2200).contains(&value) => Some(value),
        _ => None,
    }
}

/// Parses `MM/YY`, `MM/YYYY`, `MM-YY`, `MMYY`, `YYYY-MM`, `YYYY-MM-DD`,
/// `DD.MM.YYYY`, `MM.YYYY` and `DD/MM/YYYY`.
pub fn parse(value: &str) -> Option<Expiry> {
    let value = value.trim();
    let parts: Vec<&str> = value
        .split(['/', '-', '.', ' '])
        .filter(|p| !p.is_empty())
        .collect();
    if parts.iter().any(|p| !p.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let month_only = |year: i32, month: u32| {
        (1..=12).contains(&month).then(|| Expiry {
            year,
            month,
            day: days_in_month(year, month),
            month_only: true,
        })
    };
    let full = |year: i32, month: u32, day: u32| {
        ((1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month)).then_some(
            Expiry {
                year,
                month,
                day,
                month_only: false,
            },
        )
    };
    match parts.as_slice() {
        [compact] if compact.len() == 4 => {
            month_only(year_of(&compact[2..])?, compact[..2].parse().ok()?)
        }
        [a, b] if a.len() == 4 => month_only(year_of(a)?, b.parse().ok()?),
        [a, b] if a.len() <= 2 => month_only(year_of(b)?, a.parse().ok()?),
        [a, b, c] if a.len() == 4 => full(year_of(a)?, b.parse().ok()?, c.parse().ok()?),
        [a, b, c] if c.len() == 4 => full(year_of(c)?, b.parse().ok()?, a.parse().ok()?),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_card_and_document_dates() {
        assert_eq!(parse("05/27").unwrap().display(), "2027-05");
        assert_eq!(parse("5/2027").unwrap().display(), "2027-05");
        assert_eq!(parse("0527").unwrap().display(), "2027-05");
        assert_eq!(parse("2027-05").unwrap().display(), "2027-05");
        assert_eq!(parse("2031-02-28").unwrap().display(), "2031-02-28");
        assert_eq!(parse("28.02.2031").unwrap().display(), "2031-02-28");
        assert_eq!(parse("02/2024").unwrap().day, 29);
        assert_eq!(parse("13/27"), None);
        assert_eq!(parse("30.02.2031"), None);
        assert_eq!(parse("soon"), None);
        assert_eq!(parse(""), None);
    }

    #[test]
    fn counts_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(
            parse("12/99").unwrap().last_day(),
            days_from_civil(2099, 12, 31)
        );
    }
}
