// ABOUTME: Exposes in-package test helpers to the epss_test integration tests.
// ABOUTME: Those tests live in an external package because testutil imports epss.
package epss

// CaptureWarnings exposes captureWarnings to the epss_test package.
var CaptureWarnings = captureWarnings
