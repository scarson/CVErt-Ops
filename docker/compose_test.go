// ABOUTME: Tests the Docker Compose stacks: which settings reach the app, required secrets, and published ports.
// ABOUTME: Rendering needs only the docker CLI; the app-role script test runs a real Postgres container.
package docker_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"go.yaml.in/yaml/v4"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const (
	baseFile       = "compose.yml"
	productionFile = "compose.prod.yml"
	// developmentAppPassword is the value .env.example gives APP_DB_PASSWORD.
	developmentAppPassword = "cvert_ops_app_dev" //nolint:gosec // G101: the public .env.example value this test keeps out of production
)

// settingsWithheldFromApp lists config settings deliberately absent from the
// app service, each with the reason.
var settingsWithheldFromApp = map[string]string{
	"DATABASE_URL_MIGRATE": "holds the superuser credential, which only the migrate service uses",
}

// settingsReadOutsideConfig lists settings the binary reads with os.Getenv
// rather than through config.Config.
var settingsReadOutsideConfig = []string{"GITHUB_TOKEN"}

// configSettings returns every environment variable config.Config reads.
func configSettings(t *testing.T) []string {
	t.Helper()
	typ := reflect.TypeFor[config.Config]()
	settings := make([]string, 0, typ.NumField())
	for field := range typ.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("env"), ",")
		if name == "" {
			t.Fatalf("config.Config.%s has no env tag", field.Name)
		}
		settings = append(settings, name)
	}
	return settings
}

// declaredAppEnvironment returns the keys the compose file sets on the app service.
func declaredAppEnvironment(t *testing.T, file string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(file) //nolint:gosec // G304: fixed file names in this directory
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var doc struct {
		Services struct {
			App struct {
				Environment map[string]any `yaml:"environment"`
			} `yaml:"app"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}
	return doc.Services.App.Environment
}

// TestProductionAppReceivesEverySetting fails when a new setting is added to
// config.Config without a route into the production app container.
func TestProductionAppReceivesEverySetting(t *testing.T) {
	t.Parallel()
	declared := declaredAppEnvironment(t, baseFile)
	maps.Copy(declared, declaredAppEnvironment(t, productionFile))

	settings := append(configSettings(t), settingsReadOutsideConfig...)
	for _, setting := range settings {
		if _, withheld := settingsWithheldFromApp[setting]; withheld {
			continue
		}
		if _, ok := declared[setting]; !ok {
			t.Errorf("%s is read by the binary but not set on the app service in %s", setting, productionFile)
		}
	}
	for setting, reason := range settingsWithheldFromApp {
		if !slices.Contains(settings, setting) {
			t.Errorf("%s is listed as withheld (%s) but the binary does not read it", setting, reason)
		}
		if _, ok := declared[setting]; ok {
			t.Errorf("%s must not reach the app service: %s", setting, reason)
		}
	}
}

type renderedService struct {
	Environment map[string]*string `json:"environment"`
	Ports       []struct {
		Target    int    `json:"target"`
		Published string `json:"published"`
	} `json:"ports"`
	Networks map[string]any `json:"networks"`
}

type renderedStack struct {
	Services map[string]renderedService `json:"services"`
}

// renderCompose runs `docker compose config` with only envFile for settings,
// so values in the caller's shell cannot change the outcome. It returns the
// rendered JSON, or the command's stderr in the error.
func renderCompose(t *testing.T, envFile string, files ...string) (string, error) {
	t.Helper()
	args := []string{"compose"}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	args = append(args, "--profile", "app", "--env-file", envFile, "config", "--format", "json")
	cmd := exec.CommandContext(t.Context(), "docker", args...) //nolint:gosec // G204: fixed arguments
	cmd.Env = dockerClientEnvironment()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

// dockerClientEnvironment keeps only what the docker CLI needs to find its
// plugins and configuration.
func dockerClientEnvironment() []string {
	keep := []string{
		"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP",
		"APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "DOCKER_CONFIG", "DOCKER_HOST",
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if slices.Contains(keep, strings.ToUpper(name)) {
			env = append(env, kv)
		}
	}
	return env
}

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stack.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write env file: %v", err)
	}
	return path
}

func parseRender(t *testing.T, rendered string) renderedStack {
	t.Helper()
	var stack renderedStack
	if err := json.Unmarshal([]byte(rendered), &stack); err != nil {
		t.Fatalf("parse rendered stack: %v", err)
	}
	return stack
}

const requiredWithoutAppPassword = "POSTGRES_PASSWORD=test-superuser-password\n" +
	"JWT_SECRET=0123456789012345678901234567890123456789\n"

func TestComposeRefusesToRenderWithoutAppPassword(t *testing.T) {
	t.Parallel()
	for name, files := range map[string][]string{
		"development": {baseFile},
		"production":  {baseFile, productionFile},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := renderCompose(t, writeEnvFile(t, requiredWithoutAppPassword), files...)
			if err == nil {
				t.Fatal("render succeeded without APP_DB_PASSWORD")
			}
			if !strings.Contains(err.Error(), "APP_DB_PASSWORD") {
				t.Errorf("error does not name the missing variable: %v", err)
			}
		})
	}
}

func TestProductionRenderCarriesOperatorSettings(t *testing.T) {
	t.Parallel()
	envFile := writeEnvFile(t, requiredWithoutAppPassword+
		"APP_DB_PASSWORD=test-app-password\n"+
		"WEBHOOK_PRIVATE_HOSTS=ntfy.example.test\n"+
		"TRUSTED_PROXIES=172.16.0.0/12\n"+
		"SMTP_HOST=smtp.example.test\n"+
		"SMTP_PORT=587\n"+
		"GITHUB_TOKEN=test-github-token\n")
	rendered, err := renderCompose(t, envFile, baseFile, productionFile)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(rendered, developmentAppPassword) {
		t.Error("production render contains the development app password")
	}

	app := parseRender(t, rendered).Services["app"]
	for key, want := range map[string]string{ //nolint:gosec // G101: placeholder values for this render only
		"WEBHOOK_PRIVATE_HOSTS": "ntfy.example.test",
		"TRUSTED_PROXIES":       "172.16.0.0/12",
		"SMTP_HOST":             "smtp.example.test",
		"SMTP_PORT":             "587",
		"GITHUB_TOKEN":          "test-github-token",
	} {
		if got := app.Environment[key]; got == nil || *got != want {
			t.Errorf("app %s = %v, want %q", key, got, want)
		}
	}
	databaseURL := app.Environment["DATABASE_URL"]
	if databaseURL == nil || !strings.Contains(*databaseURL, "cvert_ops_app:test-app-password@") {
		t.Errorf("app DATABASE_URL does not use the app role and password: %v", databaseURL)
	}
	if got := app.Environment["GEMINI_API_KEY"]; got != nil {
		t.Errorf("unset GEMINI_API_KEY reached the app as %q; unset settings must fall back to the app's default", *got)
	}
	if _, ok := app.Environment["POSTGRES_PASSWORD"]; ok {
		t.Error("the Postgres superuser password reached the app service")
	}
}

func TestProductionPublishesOnlyCaddy(t *testing.T) {
	t.Parallel()
	envFile := writeEnvFile(t, requiredWithoutAppPassword+"APP_DB_PASSWORD=test-app-password\n")
	rendered, err := renderCompose(t, envFile, baseFile, productionFile)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	stack := parseRender(t, rendered)

	for name, service := range stack.Services {
		if name == "caddy" {
			continue
		}
		if len(service.Ports) != 0 {
			t.Errorf("%s publishes host ports %+v; only caddy may", name, service.Ports)
		}
	}
	if got := len(stack.Services["caddy"].Ports); got != 2 {
		t.Errorf("caddy publishes %d ports, want 2", got)
	}
	if _, ok := stack.Services["mailpit"]; ok {
		t.Error("mailpit runs in the production stack")
	}
	if networks := slices.Collect(maps.Keys(stack.Services["postgres"].Networks)); !slices.Equal(networks, []string{"cvert-data-net"}) {
		t.Errorf("postgres networks = %v, want only cvert-data-net", networks)
	}
}

// TestDevelopmentStackRendersFromEnvExample keeps the documented first run
// working: copy .env.example, set JWT_SECRET, start.
func TestDevelopmentStackRendersFromEnvExample(t *testing.T) {
	t.Parallel()
	example, err := os.ReadFile("../.env.example")
	if err != nil {
		t.Fatalf("read .env.example: %v", err)
	}
	envFile := writeEnvFile(t, string(example)+"\nJWT_SECRET=0123456789012345678901234567890123456789\n")
	rendered, err := renderCompose(t, envFile, baseFile)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	stack := parseRender(t, rendered)
	for _, name := range []string{"postgres", "mailpit", "app"} {
		if len(stack.Services[name].Ports) == 0 {
			t.Errorf("%s publishes no host ports in the development stack", name)
		}
	}
	if smtp := stack.Services["app"].Environment["SMTP_HOST"]; smtp == nil || *smtp != "mailpit" {
		t.Errorf("development SMTP_HOST = %v, want mailpit", smtp)
	}
}

// TestNoComposeFileHoldsAnAppPassword keeps credentials in .env, where
// production replaces them.
func TestNoComposeFileHoldsAnAppPassword(t *testing.T) {
	t.Parallel()
	for _, file := range []string{baseFile, productionFile, "init-app-role.sh"} {
		data, err := os.ReadFile(file) //nolint:gosec // G304: fixed file names in this directory
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if bytes.Contains(data, []byte(developmentAppPassword)) {
			t.Errorf("%s contains the development app password", file)
		}
	}
}

// TestContainerScriptsUseLFLineEndings guards the scripts mounted into
// containers: a CRLF shebang line stops the container from starting.
func TestContainerScriptsUseLFLineEndings(t *testing.T) {
	t.Parallel()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".sh" {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: paths come from walking this directory
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("\r")) {
			t.Errorf("%s has CRLF line endings", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// startInitializedPostgres runs Postgres with init-app-role.sh in its init
// directory, against a database named differently from the production default.
func startInitializedPostgres(ctx context.Context, env map[string]string) (*tcpostgres.PostgresContainer, error) {
	owner, err := testutil.OwnerOption()
	if err != nil {
		return nil, err
	}
	return tcpostgres.Run(ctx, "postgres:18-alpine",
		tcpostgres.WithDatabase("stack_db"),
		tcpostgres.WithUsername("stack_admin"),
		tcpostgres.WithPassword("stack-admin-password"),
		tcpostgres.WithInitScripts("init-app-role.sh"),
		tcpostgres.BasicWaitStrategies(),
		testcontainers.WithEnv(env),
		owner,
	)
}

func TestAppRoleScriptCreatesRestrictedRoleWithConfiguredPassword(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	// Quotes, a dollar sign and a backslash would break unquoted SQL or shell expansion.
	const password = `pa'ss"wo$rd\1` //nolint:gosec // G101: password of a throwaway test container
	ctr, err := startInitializedPostgres(ctx, map[string]string{"APP_DB_PASSWORD": password})
	if ctr != nil {
		t.Cleanup(func() {
			if termErr := ctr.Terminate(context.Background()); termErr != nil {
				t.Errorf("terminate: %v", termErr)
			}
		})
	}
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	connStr, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	connectAs := func(user, pw string) (*pgx.Conn, error) {
		cfg, err := pgx.ParseConfig(connStr)
		if err != nil {
			t.Fatalf("parse connection string: %v", err)
		}
		cfg.User, cfg.Password = user, pw
		return pgx.ConnectConfig(ctx, cfg)
	}

	wrong, err := connectAs("cvert_ops_app", developmentAppPassword)
	if err == nil {
		_ = wrong.Close(ctx)
		t.Error("the app role accepted the development password")
	}

	admin, err := connectAs("stack_admin", "stack-admin-password")
	if err != nil {
		t.Fatalf("connect as admin: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	if _, err := admin.Exec(ctx, "CREATE TABLE created_by_migration (id bigserial PRIMARY KEY)"); err != nil {
		t.Fatalf("create table: %v", err)
	}

	app, err := connectAs("cvert_ops_app", password)
	if err != nil {
		t.Fatalf("connect as cvert_ops_app with the configured password: %v", err)
	}
	t.Cleanup(func() { _ = app.Close(context.Background()) })

	var super, bypassRLS, createDB, createRole bool
	if err := app.QueryRow(ctx, `SELECT rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
		FROM pg_roles WHERE rolname = current_user`).Scan(&super, &bypassRLS, &createDB, &createRole); err != nil {
		t.Fatalf("read role attributes: %v", err)
	}
	if super || bypassRLS || createDB || createRole {
		t.Errorf("role attributes: super=%v bypassrls=%v createdb=%v createrole=%v, want all false",
			super, bypassRLS, createDB, createRole)
	}
	if _, err := app.Exec(ctx, "INSERT INTO created_by_migration DEFAULT VALUES"); err != nil {
		t.Errorf("default privileges do not cover tables and sequences a migration creates: %v", err)
	}
}

func TestAppRoleScriptFailsInitializationWithoutPassword(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	ctr, err := startInitializedPostgres(ctx, nil)
	if ctr == nil {
		t.Fatalf("container was not created: %v", err)
	}
	t.Cleanup(func() {
		if termErr := ctr.Terminate(context.Background()); termErr != nil {
			t.Errorf("terminate: %v", termErr)
		}
	})
	if err == nil {
		t.Fatal("Postgres finished initializing without APP_DB_PASSWORD")
	}
	logs, err := ctr.Logs(ctx)
	if err != nil {
		t.Fatalf("read container logs: %v", err)
	}
	defer logs.Close() //nolint:errcheck
	output, err := io.ReadAll(logs)
	if err != nil {
		t.Fatalf("read container logs: %v", err)
	}
	if !bytes.Contains(output, []byte("APP_DB_PASSWORD must be set")) {
		t.Errorf("initialization did not stop on the script's check; container logs:\n%s", output)
	}
}
