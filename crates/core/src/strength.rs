//! Password strength estimation with zxcvbn, extended with common German
//! words and names. Every client uses this, so web, desktop and mobile rate
//! a password the same way.

use std::sync::OnceLock;

use zxcvbn::feedback::{Suggestion, Warning};

/// Passwords longer than this are rated by their first characters only;
/// zxcvbn gets slow on very long input and such passwords are strong anyway.
const MAX_ANALYZED_CHARS: usize = 64;

/// The minimum for a master password: score and length.
pub const MASTER_PASSWORD_MIN_SCORE: u8 = 3;
pub const MASTER_PASSWORD_MIN_CHARS: usize = 12;

/// Common German words, names and password bases that zxcvbn's English
/// dictionaries miss. Lowercase, most common first.
const GERMAN: &[&str] = &[
    "passwort",
    "kennwort",
    "hallo",
    "schatz",
    "sommer",
    "winter",
    "fruehling",
    "frühling",
    "herbst",
    "januar",
    "februar",
    "maerz",
    "märz",
    "april",
    "mai",
    "juni",
    "juli",
    "august",
    "september",
    "oktober",
    "november",
    "dezember",
    "montag",
    "dienstag",
    "mittwoch",
    "donnerstag",
    "freitag",
    "samstag",
    "sonntag",
    "liebe",
    "geheim",
    "willkommen",
    "sonne",
    "mond",
    "stern",
    "sterne",
    "blume",
    "himmel",
    "engel",
    "hund",
    "katze",
    "maus",
    "baer",
    "bär",
    "pferd",
    "vogel",
    "fisch",
    "tiger",
    "loewe",
    "löwe",
    "drache",
    "fussball",
    "fußball",
    "bayern",
    "schalke",
    "dortmund",
    "borussia",
    "werder",
    "hertha",
    "eintracht",
    "deutschland",
    "berlin",
    "hamburg",
    "muenchen",
    "münchen",
    "koeln",
    "köln",
    "frankfurt",
    "stuttgart",
    "dresden",
    "leipzig",
    "hannover",
    "bremen",
    "familie",
    "mama",
    "papa",
    "oma",
    "opa",
    "kinder",
    "kind",
    "baby",
    "freund",
    "freundin",
    "schule",
    "arbeit",
    "firma",
    "computer",
    "internet",
    "handy",
    "auto",
    "haus",
    "garten",
    "urlaub",
    "weihnachten",
    "ostern",
    "geburtstag",
    "schokolade",
    "kaffee",
    "bier",
    "wein",
    "musik",
    "gitarre",
    "zauber",
    "glueck",
    "glück",
    "gluecklich",
    "schmetterling",
    "regenbogen",
    "prinzessin",
    "koenig",
    "könig",
    "koenigin",
    "ritter",
    "teufel",
    "gott",
    "jesus",
    "maria",
    "anfang",
    "schluessel",
    "schlüssel",
    "tresor",
    "sicher",
    "sicherheit",
    "zugang",
    "anmeldung",
    "benutzer",
    "admin",
    "test",
    "start",
    "michael",
    "thomas",
    "andreas",
    "stefan",
    "peter",
    "christian",
    "markus",
    "frank",
    "klaus",
    "juergen",
    "jürgen",
    "wolfgang",
    "uwe",
    "sven",
    "tobias",
    "daniel",
    "jan",
    "lukas",
    "leon",
    "finn",
    "jonas",
    "paul",
    "felix",
    "max",
    "maximilian",
    "alexander",
    "sebastian",
    "florian",
    "matthias",
    "martin",
    "dieter",
    "hans",
    "werner",
    "manfred",
    "helmut",
    "gerhard",
    "sabine",
    "susanne",
    "petra",
    "claudia",
    "andrea",
    "nicole",
    "stefanie",
    "julia",
    "anna",
    "laura",
    "lena",
    "lea",
    "sophie",
    "sophia",
    "marie",
    "emma",
    "mia",
    "hannah",
    "lisa",
    "sarah",
    "katharina",
    "christina",
    "monika",
    "ursula",
    "renate",
    "brigitte",
    "heike",
    "birgit",
    "anja",
    "tanja",
    "sandra",
    "melanie",
    "jessica",
    "jennifer",
    "vanessa",
    "schmidt",
    "schneider",
    "fischer",
    "weber",
    "meyer",
    "meier",
    "wagner",
    "becker",
    "schulz",
    "hoffmann",
    "koch",
    "richter",
    "klein",
    "wolf",
    "schroeder",
    "neumann",
    "schwarz",
    "zimmermann",
    "braun",
    "krueger",
    "hofmann",
    "hartmann",
    "lange",
    "krause",
    "lehmann",
    "koehler",
    "mueller",
    "müller",
    "passbox",
];

/// A strength estimate. `warning` and `suggestions` are stable codes for
/// localized messages (see [`warning_code`] and [`suggestion_code`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strength {
    /// 0 (very weak) to 4 (very strong).
    pub score: u8,
    /// Estimated guesses to crack, as log2.
    pub bits: u32,
    pub warning: Option<&'static str>,
    pub suggestions: Vec<&'static str>,
}

impl Strength {
    pub fn label(&self) -> &'static str {
        ["Very weak", "Weak", "Fair", "Strong", "Very strong"][usize::from(self.score.min(4))]
    }
}

fn dictionary() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| GERMAN.to_vec())
}

/// Splits user context (email, names, server host) into words zxcvbn should
/// treat as easy to guess.
fn context_words(user_inputs: &[&str]) -> Vec<String> {
    let mut words = Vec::new();
    for input in user_inputs {
        let lower = input.trim().to_lowercase();
        if lower.is_empty() {
            continue;
        }
        words.push(lower.clone());
        for part in lower.split(|c: char| !c.is_alphanumeric()) {
            if part.chars().count() >= 3 && !words.iter().any(|w| w == part) {
                words.push(part.to_owned());
            }
        }
    }
    words
}

/// Estimates how hard `password` is to guess. `user_inputs` are things an
/// attacker would try first: the account email, the user's name, the server
/// host.
pub fn estimate(password: &str, user_inputs: &[&str]) -> Strength {
    if password.is_empty() {
        return Strength {
            score: 0,
            bits: 0,
            warning: None,
            suggestions: Vec::new(),
        };
    }
    let analyzed: String = password.chars().take(MAX_ANALYZED_CHARS).collect();
    let context = context_words(user_inputs);
    let mut inputs: Vec<&str> = context.iter().map(String::as_str).collect();
    inputs.extend_from_slice(dictionary());
    let entropy = zxcvbn::zxcvbn(&analyzed, &inputs);
    let feedback = entropy.feedback();
    let bits = (entropy.guesses_log10() * std::f64::consts::LOG2_10).round() as u32;
    let score = score_from_bits(bits);
    let mut warning = feedback.and_then(|f| f.warning()).map(warning_code);
    let mut suggestions: Vec<&'static str> = feedback
        .map(|f| {
            f.suggestions()
                .iter()
                .copied()
                .map(suggestion_code)
                .collect()
        })
        .unwrap_or_default();
    // zxcvbn only gives feedback below its own, more lenient score 3.
    if score <= 2 {
        if warning.is_none() && contains_year(&analyzed) {
            warning = Some("recent_year");
        }
        if suggestions.is_empty() {
            suggestions.push("add_words");
        }
    }
    Strength {
        score,
        bits,
        warning,
        suggestions,
    }
}

fn contains_year(password: &str) -> bool {
    let digits: Vec<char> = password.chars().collect();
    digits.windows(4).any(|w| {
        w.iter().all(char::is_ascii_digit)
            && matches!(w.iter().collect::<String>().parse::<u32>(), Ok(1900..=2099))
    })
}

/// zxcvbn's own score targets online guessing (score 3 is only 10^8
/// guesses). Passbox rates for offline attacks on a stolen device or
/// breached site, so the thresholds are stricter.
fn score_from_bits(bits: u32) -> u8 {
    match bits {
        0..20 => 0,
        20..30 => 1,
        30..40 => 2,
        40..50 => 3,
        _ => 4,
    }
}

/// Whether `password` is good enough to protect an account.
pub fn is_acceptable_master_password(password: &str, strength: &Strength) -> bool {
    strength.score >= MASTER_PASSWORD_MIN_SCORE
        && password.chars().count() >= MASTER_PASSWORD_MIN_CHARS
}

pub fn warning_code(warning: Warning) -> &'static str {
    match warning {
        Warning::StraightRowsOfKeysAreEasyToGuess => "keyboard_row",
        Warning::ShortKeyboardPatternsAreEasyToGuess => "keyboard_pattern",
        Warning::RepeatsLikeAaaAreEasyToGuess => "repeated_chars",
        Warning::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => "repeated_pattern",
        Warning::ThisIsATop10Password | Warning::ThisIsATop100Password => "top_password",
        Warning::ThisIsACommonPassword => "common_password",
        Warning::ThisIsSimilarToACommonlyUsedPassword => "similar_to_common",
        Warning::SequencesLikeAbcAreEasyToGuess => "sequence",
        Warning::RecentYearsAreEasyToGuess => "recent_year",
        Warning::AWordByItselfIsEasyToGuess => "single_word",
        Warning::DatesAreOftenEasyToGuess => "date",
        Warning::NamesAndSurnamesByThemselvesAreEasyToGuess => "name",
        Warning::CommonNamesAndSurnamesAreEasyToGuess => "common_name",
    }
}

pub fn suggestion_code(suggestion: Suggestion) -> &'static str {
    match suggestion {
        Suggestion::UseAFewWordsAvoidCommonPhrases => "use_words",
        Suggestion::NoNeedForSymbolsDigitsOrUppercaseLetters => "no_symbols_needed",
        Suggestion::AddAnotherWordOrTwo => "add_words",
        Suggestion::CapitalizationDoesntHelpVeryMuch => "capitalization",
        Suggestion::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase => "all_uppercase",
        Suggestion::ReversedWordsArentMuchHarderToGuess => "reversed",
        Suggestion::PredictableSubstitutionsDontHelpVeryMuch => "substitutions",
        Suggestion::UseALongerKeyboardPatternWithMoreTurns => "longer_keyboard_pattern",
        Suggestion::AvoidRepeatedWordsAndCharacters => "avoid_repeats",
        Suggestion::AvoidSequences => "avoid_sequences",
        Suggestion::AvoidRecentYears => "avoid_recent_years",
        Suggestion::AvoidYearsThatAreAssociatedWithYou => "avoid_personal_years",
        Suggestion::AvoidDatesAndYearsThatAreAssociatedWithYou => "avoid_personal_dates",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_common_patterns_as_weak() {
        for password in [
            "Sommer2024!",
            "Summer2024!!",
            "P@ssw0rd123!",
            "Welcome@2024",
            "Dezember2025#",
            "passwort",
            "123456",
            "qwertz123",
        ] {
            let strength = estimate(password, &[]);
            assert!(strength.score <= 2, "{password} rated {}", strength.score);
            assert!(!is_acceptable_master_password(password, &strength));
        }
    }

    #[test]
    fn uses_personal_context() {
        let email = "michael.doehler@example.com";
        let with = estimate("michael.doehler", &[email]);
        let without = estimate("michael.doehler", &[]);
        assert!(with.score < without.score.max(1), "{with:?} vs {without:?}");
        assert!(estimate("Passbox2026!", &["passbox.example.com"]).score <= 2);
    }

    #[test]
    fn accepts_long_random_passphrases() {
        let strength = estimate("correct-horse-battery-staple-Ofen", &[]);
        assert_eq!(strength.score, 4);
        assert!(is_acceptable_master_password(
            "correct-horse-battery-staple-Ofen",
            &strength
        ));
        assert!(estimate("T&=7FTXoK66Vo4lg(F2:+.?K", &[]).score == 4);
        // Long input is truncated, not slow.
        let long = crate::generator::generate_password(&crate::generator::PasswordOptions {
            length: 500,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(estimate(&long, &[]).score, 4);
    }

    #[test]
    fn reports_feedback_codes() {
        let strength = estimate("Sommer2024", &[]);
        assert!(strength.warning.is_some() || !strength.suggestions.is_empty());
        assert_eq!(estimate("", &[]).score, 0);
    }
}
