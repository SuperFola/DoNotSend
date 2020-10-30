# Changelog

## Unreleased changes
### Added
- converter.py, to encode/decode ascii in base 32 and base 64 flawlessly
- packet.py to encapsulate a lot of dull work

### Changed
- now using subdomains of a main domain instead of the qname field, in case it's filtered
- the replies come in DNS reply answer field, as TXT

### Removed

## v0.0.1
### Added
- basic client sending message in DNS question qname field
- basic server reading message from DNS question qname field, answer in DNS reply answer field