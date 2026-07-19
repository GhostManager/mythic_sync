# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.1.0] - 18 July 2026

### Added

* Added an AOF-backed Redis retry queue so Ghostwriter tag failures do not block log entry ingestion and pending jobs survive `mythic_sync` restarts and service recreation, provided the Redis data volume is preserved.
* Added Redis health checks, pending-job reporting, and automatic migration of legacy mappings and queued tag jobs.
* Added tests for query retries, stale entry reconciliation, deleted entry recreation, tag retries, and source IP formatting.
* Added GitHub Actions coverage for Python 3.10, Python 3.12, and production container builds, plus Dependabot configuration.

### Changed

* Changed Ghostwriter GraphQL retries to use exponential backoff with jitter, capped at five minutes.
* Improved GraphQL error messages with the operation name and variables, including actionable context for ambiguous `ModelDoesNotExist` responses.
* Changed source IP formatting from a JSON array to a sorted, comma-separated string.
* Made Redis hostname, port, and database configurable and scoped Redis mappings by Mythic server and Ghostwriter oplog.
* Enabled Redis append-only persistence for embedded Mythic deployments and for the standalone Compose Redis service with a named volume. Raw Mythic subscription events remain live-streamed and are not persisted locally.
* Updated supported dependency pins and moved the production container to Python 3.11 on Debian Bookworm.
* Made Mythic timestamp and IP parsing tolerant of timezone variants, IPv6, plain strings, CIDR notation, and malformed individual addresses.
* Limited GraphQL error context to identifiers while redacting commands, comments, and other potentially sensitive values.
* Made the Ghostwriter initialization entry idempotent and corrected Mythic API-key authentication so user credentials are not also required.
* Made subscription and tag worker shutdown explicit so worker failures cancel and await the remaining tasks before the Ghostwriter client closes.

### Fixed

* Fixed stale Redis entry mappings by looking up the Ghostwriter entry by `entryIdentifier` and repairing the mapping or recreating a deleted entry.
* Prevented repeated Mythic error notifications and notification delivery failures from interfering with GraphQL retries.
* Fixed Redis startup checks reporting success without issuing a command.
* Fixed conversion, creation, update, and Redis failures being swallowed after logging, which could allow processing to continue after an entry failed.
* Fixed timezone-aware token expiration parsing for timestamps ending in `Z`.

## [3.0.8] - 25 July 2025

### Changed

* Using Ghostwriter's new tags and setTags GraphQL calls, sync over Mythic's tagging to oplog entries
  * Mythic-based tags are prefixed with `mythic:`
  
## [3.0.7] - 27 June 2024

### Changed

* fixed null entries in oplog inserts for output and command values to be explicit or removed
* updated query execute function to use self.client.connect_async reconnecting AIOHTTP transport instead of making a new session each time

## [3.0.6] - 8 April 2024

### Changed

* Fixed one issue of `entryIdentifier`
* Added placeholder `{}` values for `extraFields` in oplog entry creation mutations

## [3.0.5] - 5 April 2024

### Changed

* Changed references to the `entry_identifier` field to `entryIdentifier` for Ghostwriter v4.1

## [3.0.4] - 14 December 2023

### Changed

* Added check for `entry_identifier` in Ghostwriter before submitting entries

## [3.0.3] - 08 December 2023

### Changed

* Adjusted the Ghostwriter messages to more closely mirror that of cobalt_sync
* Adjusted the IP sorting to remove CIDR notations

## [3.0.2] - 13 June 2023

### Fixed

* Handled an exception caused by `_check_token()` trying to parse the expiration date from a token that never expires

## [3.0.1] - 17 May 2023

### Changed

* The Mythic Sync service will now check your Ghostwriter API token's expiration date and send a warning if it expires within 24 hours
* Added suggestions for possible solutions to GraphQL errors that can be caused by providing an invalid or expired API token or an incorrect/non-existent log ID

## [3.0.0] - 11 May 2023

### Changed

* Updated for compatibility with Mythic v3.0.0

## [2.0.2] - 14 February 2023

### Added

* The Mythic Sync service will now send messages to Mythic's notification center when it starts and whenever it logs an exception that should be reviewed

### Changed

* Web requests now use the user agent `Mythic_Sync/<Version>` to make them easily identifiable in server logs

## [2.0.1] - 4 August 2022

### Changed

* Changed log format to include timestamps consistent with Ghostwriter for easier log entry comparisons (Closes #6)

## [2.0.0] - 1 August 2022

### Added

* Added a log handler for new agent callbacks

### Changed

* Switched to using Ghostwriter v3's GraphQL API

### Deprecated

* Deprecated support for Ghostwriter v2's REST API
  * `mythic_sync` now uses Ghostwriter v3's GraphQL API keys (generated by visiting your user profile)
  * Use the `Ghostwriter-v2.x` branch to continue using `mythic_sync` with Ghostwriter v2.x.x
