use std::fmt;

use thiserror::Error;

const MINIMUM_PASSWORD_CHARACTERS: usize = 15;
const MAXIMUM_PASSWORD_CHARACTERS: usize = 1024;
const BLOCKED_PASSWORDS: &[&str] = &[
    "123456789012345",
    "passwordpassword",
    "password123456",
    "qwertyuiopasdfg",
    "correcthorsebatterystaple",
    "senha123456789",
];

#[derive(Clone, PartialEq, Eq)]
pub struct NormalizedEmail(String);

impl NormalizedEmail {
    pub fn parse(value: &str) -> Result<Self, EmailError> {
        let normalized = value.trim().to_ascii_lowercase();
        if normalized.len() > 254 || !normalized.is_ascii() {
            return Err(EmailError::Invalid);
        }
        let Some((local, domain)) = normalized.split_once('@') else {
            return Err(EmailError::Invalid);
        };
        if local.is_empty()
            || local.len() > 64
            || domain.is_empty()
            || domain.starts_with('.')
            || domain.ends_with('.')
            || domain.contains("..")
            || !domain.contains('.')
            || normalized.matches('@').count() != 1
        {
            return Err(EmailError::Invalid);
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NormalizedEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedEmail([REDACTED])")
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EmailError {
    #[error("endereço de e-mail inválido")]
    Invalid,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PasswordPolicy;

impl PasswordPolicy {
    pub fn validate(&self, password: &str) -> Result<(), PasswordPolicyError> {
        let characters = password.chars().count();
        if characters < MINIMUM_PASSWORD_CHARACTERS {
            return Err(PasswordPolicyError::TooShort);
        }
        if characters > MAXIMUM_PASSWORD_CHARACTERS {
            return Err(PasswordPolicyError::TooLong);
        }
        if BLOCKED_PASSWORDS
            .iter()
            .any(|blocked| password.eq_ignore_ascii_case(blocked))
        {
            return Err(PasswordPolicyError::Blocked);
        }
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordPolicyError {
    #[error("senha deve possuir pelo menos 15 caracteres")]
    TooShort,
    #[error("senha excede o limite suportado")]
    TooLong,
    #[error("senha consta na blocklist")]
    Blocked,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_trimmed_and_ascii_case_folded() {
        let email = NormalizedEmail::parse("  Person@Example.COM ").unwrap();
        assert_eq!(email.as_str(), "person@example.com");
        assert!(!format!("{email:?}").contains("person"));
    }

    #[test]
    fn rejects_invalid_email_shapes() {
        for email in [
            "missing-at.example",
            "a@@example.com",
            "a@localhost",
            "a@.example.com",
        ] {
            assert_eq!(NormalizedEmail::parse(email), Err(EmailError::Invalid));
        }
    }

    #[test]
    fn password_policy_accepts_long_passphrases_and_rejects_blocklist() {
        let policy = PasswordPolicy;
        assert!(policy.validate("uma frase longa e exclusiva").is_ok());
        assert_eq!(
            policy.validate("passwordpassword"),
            Err(PasswordPolicyError::Blocked)
        );
        assert_eq!(policy.validate("curta"), Err(PasswordPolicyError::TooShort));
        assert!(policy.validate(&"a".repeat(64)).is_ok());
    }
}
