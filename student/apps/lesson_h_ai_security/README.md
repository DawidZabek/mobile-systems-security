# Lesson H AI Security Suite

Starter app suite for the next BSM mobile security lab.

This lesson continues the earlier labs and focuses on source-code scanning, APK-level inspection, AI-assisted vulnerability classification, disagreement handling, and patch verification.

## Apps in this suite

- `InsecureNotes`
- `FakeBankLite`
- `SecurePatchTarget_v1`
- `SecurePatchTarget_v2`

## Notebook linkage

The lab notebook lives in:

- `student/labs/BSM_L08_AI_Mobile_Security_Assessment.ipynb`

## Intended task mapping

- `H01`: source-code scan of `InsecureNotes`
- `H02`: MobSF APK analysis of `FakeBankLite.apk`
- `H03`: security-specific model classification of an `InsecureNotes` snippet
- `H04`: scanner vs AI disagreement check
- `H05`: patch verification with `SecurePatchTarget_v1/v2`

## Safety constraints

- All secrets are fake.
- The APKs are lab-only and do not talk to real services.
- The answer strings are canonical codes, not free-form explanations.
