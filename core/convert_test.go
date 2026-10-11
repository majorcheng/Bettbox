package main

import (
	"strings"
	"testing"
)

func TestHandleConvertV2Ray(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443" +
		"?security=reality&type=xhttp&sni=cover.example.com" +
		"&fp=chrome&pbk=public-key&sid=00112233" +
		"&path=%2Fvless-xhttp&host=cover.example.com&mode=stream-one"

	content, err := handleConvertV2Ray(link)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name: vless", "network: xhttp", "reality-opts:", "support-x25519mlkem768: true", "xhttp-opts:"} {
		if !strings.Contains(content, want) {
			t.Fatalf("converted config does not contain %q:\n%s", want, content)
		}
	}
}

func TestHandleConvertV2RayRejectsInvalidInput(t *testing.T) {
	if _, err := handleConvertV2Ray("vless://"); err == nil {
		t.Fatal("expected invalid VLESS link to fail")
	}
}
