// ABOUTME: Unit tests for the shared CSAF 2.0 parser.
// ABOUTME: Verifies document parsing and product tree lookup map construction.
package csaf

import (
	"strings"
	"testing"
)

const minimalCSAF = `{
  "document": {
    "title": "Test Advisory",
    "type": "csaf_security_advisory",
    "publisher": {"name": "Test Vendor", "namespace": "https://test.example.com"},
    "tracking": {
      "id": "TEST-2025-001",
      "status": "final",
      "version": "1.0",
      "initial_release_date": "2025-01-15T00:00:00Z",
      "current_release_date": "2025-02-01T00:00:00Z",
      "revision_history": [
        {"date": "2025-01-15T00:00:00Z", "number": "1.0", "summary": "Initial release"}
      ]
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "Test Vendor",
        "branches": [
          {
            "category": "product_name",
            "name": "Widget Pro",
            "branches": [
              {
                "category": "product_version",
                "name": "1.0",
                "product": {
                  "product_id": "WIDGET-PRO-1.0",
                  "name": "Test Vendor Widget Pro 1.0"
                }
              }
            ]
          }
        ]
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2025-0001",
      "title": "Widget Pro Remote Code Execution",
      "notes": [
        {"type": "description", "text": "A remote code execution vulnerability exists."}
      ],
      "scores": [
        {
          "cvss_v3": {
            "version": "3.1",
            "baseScore": 9.8,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
          },
          "products": ["WIDGET-PRO-1.0"]
        }
      ],
      "product_status": {
        "known_affected": ["WIDGET-PRO-1.0"]
      },
      "remediations": [
        {
          "category": "vendor_fix",
          "details": "Update to version 1.1",
          "url": "https://test.example.com/advisory/001",
          "product_ids": ["WIDGET-PRO-1.0"]
        }
      ],
      "threats": [
        {
          "category": "impact",
          "details": "Critical"
        }
      ],
      "references": [
        {"url": "https://test.example.com/cve/2025-0001", "summary": "Advisory page"}
      ]
    }
  ]
}`

func TestParse_MinimalDocument(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(minimalCSAF))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if doc.DocumentMeta.Title != "Test Advisory" {
		t.Errorf("Title = %q, want %q", doc.DocumentMeta.Title, "Test Advisory")
	}
	if doc.DocumentMeta.Tracking.ID != "TEST-2025-001" {
		t.Errorf("Tracking.ID = %q, want %q", doc.DocumentMeta.Tracking.ID, "TEST-2025-001")
	}
	if doc.DocumentMeta.Tracking.Status != "final" {
		t.Errorf("Tracking.Status = %q, want %q", doc.DocumentMeta.Tracking.Status, "final")
	}
	if doc.DocumentMeta.Tracking.CurrentReleaseDate != "2025-02-01T00:00:00Z" {
		t.Errorf("CurrentReleaseDate = %q, want %q", doc.DocumentMeta.Tracking.CurrentReleaseDate, "2025-02-01T00:00:00Z")
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("len(Vulnerabilities) = %d, want 1", len(doc.Vulnerabilities))
	}
	vuln := doc.Vulnerabilities[0]
	if vuln.CVE != "CVE-2025-0001" {
		t.Errorf("CVE = %q, want %q", vuln.CVE, "CVE-2025-0001")
	}
	if vuln.Title != "Widget Pro Remote Code Execution" {
		t.Errorf("Title = %q, want %q", vuln.Title, "Widget Pro Remote Code Execution")
	}
	if len(vuln.Scores) != 1 {
		t.Fatalf("len(Scores) = %d, want 1", len(vuln.Scores))
	}
	if vuln.Scores[0].CVSSv3.BaseScore != 9.8 {
		t.Errorf("CVSSv3.BaseScore = %v, want 9.8", vuln.Scores[0].CVSSv3.BaseScore)
	}
}

func TestProductTree_Lookup(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(minimalCSAF))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	lookup := doc.ProductTree.Lookup()
	name, ok := lookup["WIDGET-PRO-1.0"]
	if !ok {
		t.Fatal("product WIDGET-PRO-1.0 not found in lookup")
	}
	if name != "Test Vendor Widget Pro 1.0" {
		t.Errorf("product name = %q, want %q", name, "Test Vendor Widget Pro 1.0")
	}
}

func TestParse_EmptyDocument(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(`{"document":{"title":"Empty","tracking":{"id":"E"}}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.DocumentMeta.Title != "Empty" {
		t.Errorf("Title = %q, want %q", doc.DocumentMeta.Title, "Empty")
	}
	if len(doc.Vulnerabilities) != 0 {
		t.Errorf("len(Vulnerabilities) = %d, want 0", len(doc.Vulnerabilities))
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := Parse(strings.NewReader(`{not valid json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestProductTree_NestedBranches(t *testing.T) {
	t.Parallel()

	doc, err := Parse(strings.NewReader(`{
		"document": {"title": "T", "tracking": {"id": "T"}},
		"product_tree": {
			"branches": [{
				"category": "vendor",
				"name": "Vendor A",
				"branches": [{
					"category": "product_family",
					"name": "Family X",
					"branches": [
						{
							"category": "product_name",
							"name": "Product Y",
							"product": {"product_id": "PY", "name": "Vendor A Family X Product Y"}
						},
						{
							"category": "product_name",
							"name": "Product Z",
							"branches": [{
								"category": "product_version",
								"name": "2.0",
								"product": {"product_id": "PZ-2.0", "name": "Vendor A Family X Product Z 2.0"}
							}]
						}
					]
				}]
			}]
		}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	lookup := doc.ProductTree.Lookup()
	if len(lookup) != 2 {
		t.Fatalf("len(lookup) = %d, want 2", len(lookup))
	}
	if lookup["PY"] != "Vendor A Family X Product Y" {
		t.Errorf("PY = %q, want %q", lookup["PY"], "Vendor A Family X Product Y")
	}
	if lookup["PZ-2.0"] != "Vendor A Family X Product Z 2.0" {
		t.Errorf("PZ-2.0 = %q, want %q", lookup["PZ-2.0"], "Vendor A Family X Product Z 2.0")
	}
}
