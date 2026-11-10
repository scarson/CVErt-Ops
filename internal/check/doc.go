// ABOUTME: Package check holds the pure verdict code for the version check endpoint.
// ABOUTME: It parses request items and decides verdicts from candidate rows; it reads no database.

// Package check parses version check request items and decides, from candidate
// rows that the store has read, whether each advisory affects each component. It
// does no database access, so every rule is tested with table tests.
package check
