package main

import "testing"

func TestPublicTextIsExact(t *testing.T) {
	if productName != "Sigma Operator Stack" || statusText != "SOS is installed" || versionText != "Version 0.1.0a3" {
		t.Fatal("Store entrypoint product text drifted")
	}
	if instruction != "Install SOS in my current project. Show me the preview before changing it." {
		t.Fatal("Store entrypoint instruction drifted")
	}
}
