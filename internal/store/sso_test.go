// ABOUTME: Integration tests for SSO connection and email domain store methods.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestSSOConnection_CreateAndGet(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSOOrg1")

	conn, err := db.CreateSSOConnection(ctx, org.ID, "Acme IdP", "https://idp.example.com", "my-client-id", []byte("encrypted-secret"), []string{"openid", "profile"}, false)
	if err != nil {
		t.Fatalf("CreateSSOConnection: %v", err)
	}
	if conn.DisplayName != "Acme IdP" {
		t.Errorf("DisplayName = %q, want %q", conn.DisplayName, "Acme IdP")
	}
	if conn.IssuerUrl != "https://idp.example.com" {
		t.Errorf("IssuerUrl = %q, want %q", conn.IssuerUrl, "https://idp.example.com")
	}
	if conn.ClientID != "my-client-id" {
		t.Errorf("ClientID = %q, want %q", conn.ClientID, "my-client-id")
	}
	if string(conn.ClientSecretEnc) != "encrypted-secret" {
		t.Errorf("ClientSecretEnc mismatch")
	}
	if conn.Enabled {
		t.Error("expected Enabled = false")
	}

	// Get by org ID.
	got, err := db.GetSSOConnection(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetSSOConnection: %v", err)
	}
	if got == nil {
		t.Fatal("GetSSOConnection returned nil")
	}
	if got.ID != conn.ID {
		t.Errorf("ID mismatch: got %v, want %v", got.ID, conn.ID)
	}
	if got.DisplayName != "Acme IdP" {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, "Acme IdP")
	}
}

func TestSSOConnection_UniquePerOrg(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSOUniqueOrg")

	_, err := db.CreateSSOConnection(ctx, org.ID, "First", "https://idp1.example.com", "client1", []byte("enc1"), nil, false)
	if err != nil {
		t.Fatalf("first create: %v", err)
	}

	_, err = db.CreateSSOConnection(ctx, org.ID, "Second", "https://idp2.example.com", "client2", []byte("enc2"), nil, false)
	if err == nil {
		t.Fatal("expected error creating second SSO connection for same org, got nil")
	}
}

func TestSSOConnection_Update(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSOUpdateOrg")

	_, err := db.CreateSSOConnection(ctx, org.ID, "Original", "https://idp.example.com", "client1", []byte("enc1"), nil, false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	err = db.UpdateSSOConnection(ctx, org.ID, "Updated", "https://new-idp.example.com", "new-client", []byte("enc2"), []string{"openid"}, true)
	if err != nil {
		t.Fatalf("UpdateSSOConnection: %v", err)
	}

	got, err := db.GetSSOConnection(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetSSOConnection: %v", err)
	}
	if got.DisplayName != "Updated" {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, "Updated")
	}
	if got.IssuerUrl != "https://new-idp.example.com" {
		t.Errorf("IssuerUrl = %q, want %q", got.IssuerUrl, "https://new-idp.example.com")
	}
	if got.ClientID != "new-client" {
		t.Errorf("ClientID = %q, want %q", got.ClientID, "new-client")
	}
	if !got.Enabled {
		t.Error("expected Enabled = true after update")
	}
}

func TestSSOConnection_Delete(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSODeleteOrg")

	_, err := db.CreateSSOConnection(ctx, org.ID, "ToDelete", "https://idp.example.com", "client1", []byte("enc1"), nil, false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	err = db.DeleteSSOConnection(ctx, org.ID)
	if err != nil {
		t.Fatalf("DeleteSSOConnection: %v", err)
	}

	got, err := db.GetSSOConnection(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetSSOConnection after delete: %v", err)
	}
	if got != nil {
		t.Error("expected nil after delete, got non-nil")
	}
}

func TestSSOEmailDomain_CRUD(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSO_DomainOrg")

	conn, err := db.CreateSSOConnection(ctx, org.ID, "DomainTest", "https://idp.example.com", "client1", []byte("enc1"), nil, true)
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	// Add domains.
	if err := db.SetSSOEmailDomains(ctx, conn.ID, org.ID, []string{"acme.com", "acme.org"}); err != nil {
		t.Fatalf("SetSSOEmailDomains: %v", err)
	}

	// List domains.
	domains, err := db.ListSSOEmailDomains(ctx, conn.ID)
	if err != nil {
		t.Fatalf("ListSSOEmailDomains: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("domains count = %d, want 2", len(domains))
	}
	if domains[0] != "acme.com" || domains[1] != "acme.org" {
		t.Errorf("domains = %v, want [acme.com acme.org]", domains)
	}

	// Replace domains (bulk replace pattern: delete all, then insert new).
	if err := db.SetSSOEmailDomains(ctx, conn.ID, org.ID, []string{"newacme.com"}); err != nil {
		t.Fatalf("SetSSOEmailDomains (replace): %v", err)
	}
	domains, err = db.ListSSOEmailDomains(ctx, conn.ID)
	if err != nil {
		t.Fatalf("ListSSOEmailDomains after replace: %v", err)
	}
	if len(domains) != 1 || domains[0] != "newacme.com" {
		t.Errorf("domains after replace = %v, want [newacme.com]", domains)
	}
}

func TestSSOEmailDomain_Uniqueness(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := db.CreateOrg(ctx, "SSODomainUniq1")
	org2, _ := db.CreateOrg(ctx, "SSODomainUniq2")

	conn1, _ := db.CreateSSOConnection(ctx, org1.ID, "Conn1", "https://idp1.example.com", "c1", []byte("e1"), nil, true)
	conn2, _ := db.CreateSSOConnection(ctx, org2.ID, "Conn2", "https://idp2.example.com", "c2", []byte("e2"), nil, true)

	// Org1 claims "shared.com".
	if err := db.SetSSOEmailDomains(ctx, conn1.ID, org1.ID, []string{"shared.com"}); err != nil {
		t.Fatalf("org1 set domain: %v", err)
	}

	// Org2 tries to claim the same domain — should fail.
	err := db.SetSSOEmailDomains(ctx, conn2.ID, org2.ID, []string{"shared.com"})
	if err == nil {
		t.Fatal("expected error when second org claims same domain, got nil")
	}
}

func TestSSOEmailDomain_CascadeDelete(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSOCascadeOrg")

	conn, _ := db.CreateSSOConnection(ctx, org.ID, "Cascade", "https://idp.example.com", "c1", []byte("e1"), nil, true)
	if err := db.SetSSOEmailDomains(ctx, conn.ID, org.ID, []string{"cascade.com"}); err != nil {
		t.Fatalf("set domains: %v", err)
	}

	// Delete the connection — domains should cascade.
	if err := db.DeleteSSOConnection(ctx, org.ID); err != nil {
		t.Fatalf("delete connection: %v", err)
	}

	// Verify domains are gone by checking if another org can now claim it.
	org2, _ := db.CreateOrg(ctx, "SSOCascadeOrg2")
	conn2, _ := db.CreateSSOConnection(ctx, org2.ID, "After", "https://idp2.example.com", "c2", []byte("e2"), nil, true)
	if err := db.SetSSOEmailDomains(ctx, conn2.ID, org2.ID, []string{"cascade.com"}); err != nil {
		t.Fatalf("expected cascade.com to be available after cascade delete: %v", err)
	}
}

func TestSSOLookupByDomain(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSOLookupOrg")

	conn, _ := db.CreateSSOConnection(ctx, org.ID, "Lookup", "https://idp.example.com", "c1", []byte("e1"), nil, true)
	if err := db.SetSSOEmailDomains(ctx, conn.ID, org.ID, []string{"lookup.com"}); err != nil {
		t.Fatalf("set domains: %v", err)
	}

	// Lookup existing domain.
	result, err := db.LookupSSOByDomain(ctx, "lookup.com")
	if err != nil {
		t.Fatalf("LookupSSOByDomain: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result for existing domain")
	}
	if result.ID != conn.ID {
		t.Errorf("ID = %v, want %v", result.ID, conn.ID)
	}
	if result.DisplayName != "Lookup" {
		t.Errorf("DisplayName = %q, want %q", result.DisplayName, "Lookup")
	}

	// Lookup non-existent domain.
	result, err = db.LookupSSOByDomain(ctx, "nonexistent.com")
	if err != nil {
		t.Fatalf("LookupSSOByDomain (nonexistent): %v", err)
	}
	if result != nil {
		t.Error("expected nil for nonexistent domain")
	}
}

func TestSSOLookupByDomain_DisabledConnection(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSODisabledOrg")

	// Create disabled connection.
	conn, _ := db.CreateSSOConnection(ctx, org.ID, "Disabled", "https://idp.example.com", "c1", []byte("e1"), nil, false)
	if err := db.SetSSOEmailDomains(ctx, conn.ID, org.ID, []string{"disabled.com"}); err != nil {
		t.Fatalf("set domains: %v", err)
	}

	// Lookup should return nil because connection is disabled.
	result, err := db.LookupSSOByDomain(ctx, "disabled.com")
	if err != nil {
		t.Fatalf("LookupSSOByDomain: %v", err)
	}
	if result != nil {
		t.Error("expected nil for disabled connection domain")
	}
}

func TestSSOGetConnectionByID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "SSOGetByIDOrg")

	conn, _ := db.CreateSSOConnection(ctx, org.ID, "ByID", "https://idp.example.com", "c1", []byte("e1"), nil, true)

	got, err := db.GetSSOConnectionByID(ctx, conn.ID)
	if err != nil {
		t.Fatalf("GetSSOConnectionByID: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil result")
	}
	if got.DisplayName != "ByID" {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, "ByID")
	}
}
