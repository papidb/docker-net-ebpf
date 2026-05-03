package main

import "testing"

func TestParseOutputSpecsDefaults(t *testing.T) {
	t.Parallel()

	specs, err := parseOutputSpecs([]string{"jsonl", "sqlite"}, []outputSpec{{kind: "console"}})
	if err != nil {
		t.Fatalf("parseOutputSpecs returned error: %v", err)
	}

	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}

	if specs[0].kind != "jsonl" || specs[0].path != "output/traffic.jsonl" {
		t.Fatalf("unexpected first spec: %#v", specs[0])
	}

	if specs[1].kind != "sqlite" || specs[1].path != "output/traffic.db" {
		t.Fatalf("unexpected second spec: %#v", specs[1])
	}
}

func TestParseOutputSpecsExplicitPaths(t *testing.T) {
	t.Parallel()

	specs, err := parseOutputSpecs([]string{"console", "jsonl", "./tmp/traffic.jsonl", "sqlite", "./tmp/traffic.db"}, []outputSpec{{kind: "console"}})
	if err != nil {
		t.Fatalf("parseOutputSpecs returned error: %v", err)
	}

	if len(specs) != 3 {
		t.Fatalf("expected 3 specs, got %d", len(specs))
	}

	if specs[1].path != "./tmp/traffic.jsonl" {
		t.Fatalf("unexpected jsonl path: %s", specs[1].path)
	}

	if specs[2].path != "./tmp/traffic.db" {
		t.Fatalf("unexpected sqlite path: %s", specs[2].path)
	}
}

func TestParseOutputSpecsRejectsUnknownOutput(t *testing.T) {
	t.Parallel()

	if _, err := parseOutputSpecs([]string{"parquet"}, []outputSpec{{kind: "console"}}); err == nil {
		t.Fatal("expected error for unknown output")
	}
}

func TestParseOutputSpecsUsesProvidedDefaults(t *testing.T) {
	t.Parallel()

	specs, err := parseOutputSpecs(nil, []outputSpec{{kind: "jsonl", path: "output/traffic.jsonl"}})
	if err != nil {
		t.Fatalf("parseOutputSpecs returned error: %v", err)
	}

	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}

	if specs[0].kind != "jsonl" || specs[0].path != "output/traffic.jsonl" {
		t.Fatalf("unexpected default spec: %#v", specs[0])
	}
}
