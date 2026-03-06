// ABOUTME: Shared OASIS CSAF 2.0 JSON document parser.
// ABOUTME: Consumed by MSRC adapter (and later CISA ICS-CERT).
package csaf

import (
	"encoding/json"
	"fmt"
	"io"
)

// Document is the top-level CSAF 2.0 JSON structure.
type Document struct {
	DocumentMeta    DocumentMeta    `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// DocumentMeta holds CSAF document-level metadata.
type DocumentMeta struct {
	Title     string   `json:"title"`
	Type      string   `json:"type"`
	Publisher Publisher `json:"publisher"`
	Tracking  Tracking `json:"tracking"`
}

// Publisher identifies the advisory issuer.
type Publisher struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Tracking holds document versioning and release dates.
type Tracking struct {
	ID                 string          `json:"id"`
	Status             string          `json:"status"`
	Version            string          `json:"version"`
	InitialReleaseDate string          `json:"initial_release_date"`
	CurrentReleaseDate string          `json:"current_release_date"`
	RevisionHistory    []RevisionEntry `json:"revision_history"`
}

// RevisionEntry records a single revision in the document history.
type RevisionEntry struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

// ProductTree contains the hierarchical product taxonomy.
type ProductTree struct {
	Branches []Branch `json:"branches"`
}

// Branch is a recursive node in the product tree.
type Branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Product  *Product `json:"product,omitempty"`
	Branches []Branch `json:"branches,omitempty"`
}

// Product is a leaf node in the product tree with a unique ID.
type Product struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

// Vulnerability describes a single CVE within the CSAF document.
type Vulnerability struct {
	CVE             string          `json:"cve"`
	Title           string          `json:"title"`
	Notes           []Note          `json:"notes"`
	Scores          []Score         `json:"scores"`
	Remediations    []Remediation   `json:"remediations"`
	Threats         []Threat        `json:"threats"`
	ProductStatus   ProductStatus   `json:"product_status"`
	References      []Reference     `json:"references"`
	Acknowledgments []Acknowledgment `json:"acknowledgments"`
}

// Note is a typed text annotation on a vulnerability.
type Note struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Score holds CVSS scoring data for a set of products.
type Score struct {
	CVSSv3   *CVSSv3  `json:"cvss_v3,omitempty"`
	CVSSv4   *CVSSv4  `json:"cvss_v4,omitempty"`
	Products []string `json:"products"`
}

// CVSSv3 holds CVSS v3.x scoring.
type CVSSv3 struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

// CVSSv4 holds CVSS v4.0 scoring.
type CVSSv4 struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

// Remediation describes a fix or workaround.
type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	URL        string   `json:"url"`
	ProductIDs []string `json:"product_ids"`
}

// Threat describes impact or exploit status for a vulnerability.
type Threat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// ProductStatus groups product IDs by their vulnerability status.
type ProductStatus struct {
	KnownAffected    []string `json:"known_affected"`
	KnownNotAffected []string `json:"known_not_affected"`
	Fixed            []string `json:"fixed"`
}

// Reference is an external link related to a vulnerability.
type Reference struct {
	URL     string `json:"url"`
	Summary string `json:"summary"`
}

// Acknowledgment credits a reporter or contributor.
type Acknowledgment struct {
	Names []string `json:"names"`
}

// Parse reads a CSAF 2.0 JSON document from r and returns the parsed structure.
// CSAF documents are typically <1MB; reading into memory is appropriate.
func Parse(r io.Reader) (*Document, error) {
	var doc Document
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("csaf: parse document: %w", err)
	}
	return &doc, nil
}

// Lookup builds a map from ProductID to product Name by walking the recursive
// branch tree. Call once after parsing to resolve product IDs referenced in
// vulnerability sections.
func (pt *ProductTree) Lookup() map[string]string {
	m := make(map[string]string)
	for _, b := range pt.Branches {
		walkBranches(b, m)
	}
	return m
}

// walkBranches recursively walks a branch tree, collecting product ID to name
// mappings from leaf nodes.
func walkBranches(b Branch, m map[string]string) {
	if b.Product != nil && b.Product.ProductID != "" {
		m[b.Product.ProductID] = b.Product.Name
	}
	for _, child := range b.Branches {
		walkBranches(child, m)
	}
}
