package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestFilterDaemonArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no daemon args",
			in:   []string{"-config", "enode.config.yaml"},
			want: []string{"-config", "enode.config.yaml"},
		},
		{
			name: "remove daemon flags",
			in:   []string{"-daemon", "-config", "enode.config.yaml", "--daemon=true"},
			want: []string{"-config", "enode.config.yaml"},
		},
		{
			name: "remove daemon false variants",
			in:   []string{"--daemon=false", "-daemon=false", "-config", "x.yaml"},
			want: []string{"-config", "x.yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterDaemonArgs(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("filterDaemonArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveDynIPValue_Auto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("8.8.4.4\n"))
	}))
	defer server.Close()

	value, source, err := resolveDynIPValue("auto", []string{server.URL}, time.Second)
	if err != nil {
		t.Fatalf("resolveDynIPValue() error = %v", err)
	}
	if value != "8.8.4.4" {
		t.Fatalf("resolveDynIPValue() value = %q, want %q", value, "8.8.4.4")
	}
	if source != server.URL {
		t.Fatalf("resolveDynIPValue() source = %q, want %q", source, server.URL)
	}
}

func TestResolveDynIPValue_AutoFallback(t *testing.T) {
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.1.1.1"))
	}))
	defer goodServer.Close()

	value, source, err := resolveDynIPValue("auto", []string{"https://127.0.0.1:1", goodServer.URL}, time.Second)
	if err != nil {
		t.Fatalf("resolveDynIPValue() error = %v", err)
	}
	if value != "1.1.1.1" {
		t.Fatalf("resolveDynIPValue() value = %q, want %q", value, "1.1.1.1")
	}
	if source != goodServer.URL {
		t.Fatalf("resolveDynIPValue() source = %q, want %q", source, goodServer.URL)
	}
}

func TestResolveDynIPValue_Passthrough(t *testing.T) {
	value, source, err := resolveDynIPValue(" 203.0.113.10 ", nil, time.Second)
	if err != nil {
		t.Fatalf("resolveDynIPValue() error = %v", err)
	}
	if value != "203.0.113.10" {
		t.Fatalf("resolveDynIPValue() value = %q, want %q", value, "203.0.113.10")
	}
	if source != "" {
		t.Fatalf("resolveDynIPValue() source = %q, want empty", source)
	}
}
