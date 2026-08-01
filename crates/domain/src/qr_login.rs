use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChallengeStatus {
    Created,
    Scanned,
    Approved,
    Exchanged,
    Rejected,
    Expired,
    Cancelled,
}

impl ChallengeStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Exchanged | Self::Rejected | Self::Expired | Self::Cancelled
        )
    }

    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Scanned)
                | (Self::Created, Self::Expired)
                | (Self::Created, Self::Cancelled)
                | (Self::Scanned, Self::Approved)
                | (Self::Scanned, Self::Rejected)
                | (Self::Scanned, Self::Expired)
                | (Self::Scanned, Self::Cancelled)
                | (Self::Approved, Self::Exchanged)
                | (Self::Approved, Self::Expired)
                | (Self::Approved, Self::Cancelled)
        )
    }
}

#[derive(Debug, Clone)]
pub struct QrLoginChallenge {
    pub id: Uuid,
    pub status: ChallengeStatus,
    pub lock_version: i32,
    pub qr_expires_at: DateTime<Utc>,
    pub approval_expires_at: Option<DateTime<Utc>>,
}

impl QrLoginChallenge {
    pub fn transition(&mut self, next: ChallengeStatus) -> Result<(), DomainError> {
        if !self.status.can_transition_to(next) {
            return Err(DomainError::InvalidTransition {
                from: self.status,
                to: next,
            });
        }
        self.status = next;
        self.lock_version += 1;
        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("transição inválida de {from:?} para {to:?}")]
    InvalidTransition {
        from: ChallengeStatus,
        to: ChallengeStatus,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_state_cannot_transition() {
        assert!(!ChallengeStatus::Exchanged.can_transition_to(ChallengeStatus::Created));
    }

    #[test]
    fn happy_path_is_valid() {
        assert!(ChallengeStatus::Created.can_transition_to(ChallengeStatus::Scanned));
        assert!(ChallengeStatus::Scanned.can_transition_to(ChallengeStatus::Approved));
        assert!(ChallengeStatus::Approved.can_transition_to(ChallengeStatus::Exchanged));
    }
}
