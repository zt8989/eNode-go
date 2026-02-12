package main

import (
	"reflect"
	"testing"
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
