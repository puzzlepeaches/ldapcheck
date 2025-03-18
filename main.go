package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	// use our own go-ldap so we can ensure we dont include CBT
	"github.com/DriftSec/ldapcheck/ldap"
)

const (
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
)

var (
	targetArg string
	targets   []string
	dom_user  string
	user      string
	pass      string
	hash      string
	domain    string
	domQuery  string
	relayFile string
	dcFile    string
	relayLst  []string
	timeout   time.Duration
)

func main() {
	flag.StringVar(&targetArg, "t", "", "target address or file containing targets")
	flag.StringVar(&domQuery, "T", "", "Query this domain for LDAP targets")
	flag.StringVar(&dom_user, "u", "", "username, formats: user@domain or domain\\user")
	flag.StringVar(&pass, "p", "", "user password")
	flag.StringVar(&hash, "H", "", "user NTLM hash")
	flag.StringVar(&relayFile, "relay-out", "", "output file for relay targets (format: ldap[s]://host)")
	flag.StringVar(&dcFile, "dc-out", "", "output file for discovered DCs (one per line)")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "timeout for LDAP connections")
	flag.Parse()

	if targetArg == "" && domQuery == "" {
		log.Fatal("[ERROR] either target IP (-t) or target domain (-T) is required!")
	}

	if domQuery != "" {
		// query and append to targets list
		_, addr, err := net.LookupSRV("", "", "_ldap._tcp.dc._msdcs."+domQuery)
		if err != nil {
			log.Fatal("[ERROR] Failed to query _ldap._tcp.dc._msdcs."+domQuery+":", err)
		}
		for _, a := range addr {
			targets = append(targets, strings.TrimRight(a.Target, "."))
		}

		// _ldap._tcp.dc._msdcs.
	}

	if targetArg != "" {
		if _, err := os.Stat(targetArg); errors.Is(err, os.ErrNotExist) {
			targets = append(targets, targetArg)
		} else {
			tmp, err := readLines(targetArg)
			if err != nil {
				log.Fatal(err)
			}
			targets = append(targets, tmp...)
		}
	}

	if dom_user == "" {
		fmt.Println("[!] No username provided, signing check will be skipped\n")
	} else {
		if strings.Contains(dom_user, "@") {
			tmp := strings.Split(dom_user, "@")
			user = tmp[0]
			domain = tmp[1]
		} else if strings.Contains(dom_user, "/") {
			tmp := strings.Split(dom_user, "/")
			user = tmp[1]
			domain = tmp[0]
		} else if strings.Contains(dom_user, "\\") {
			tmp := strings.Split(dom_user, "\\")
			user = tmp[1]
			domain = tmp[0]
		} else {
			log.Fatal("[ERROR] Username must include the domain!")
		}

		if pass == "" && hash == "" {
			log.Fatal("[ERROR] Must specify -p or -H to authenticate")
		}
	}

	if len(targets) < 1 {
		log.Fatal("[ERROR] No targets!")
	}

	// For LDAP connections
	dialOpts := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	}

	for _, target := range targets {
		fmt.Println("[!] Checking " + target)
		successfulConnection := false

		// Check LDAP for signing, if we have creds
		if dom_user != "" {
			ldapURL := fmt.Sprintf("ldap://%s:389", target)
			l, err := ldap.DialURL(ldapURL, dialOpts...)
			if err != nil {
				if strings.Contains(err.Error(), "i/o timeout") {
					fmt.Printf("\tUnable to connect to LDAP (389): Connection timed out\n")
				} else {
					log.Printf("[ERROR] Failed to connect to %s: %v", target, err)
				}
			} else {
				defer l.Close()
				successfulConnection = true
				// err = l.Bind(user+"@"+domain, pass)
				if pass != "" {
					err = l.NTLMBind(domain, user, pass)
				} else if hash != "" {
					err = l.NTLMBindWithHash(domain, user, hash)
				} else {
					log.Fatal("[ERROR] Must specify -p or -H to authenticate")
				}

				if err != nil && strings.Contains(err.Error(), "Strong Auth Required") {
					fmt.Println(colorRed + "	signing is enforced on ldap://" + target + colorReset)
				} else if err != nil && strings.Contains(err.Error(), "Invalid Credentials") {
					fmt.Println("LDAP: Auth Failed,  valid creds are required to check signing!")
				} else {
					fmt.Println(colorGreen + "	signing is NOT enforced, we can relay to ldap://" + target + colorReset)
					relayLst = append(relayLst, "ldap://"+target)
				}
			}
		}

		// Check LDAPS for channel binding
		ldapsURL := fmt.Sprintf("ldaps://%s:636", target)
		ls, err := ldap.DialURL(ldapsURL, dialOpts...)
		if err != nil {
			if strings.Contains(err.Error(), "i/o timeout") {
				fmt.Printf("\tUnable to connect to LDAPS (636): Connection timed out\n")
			} else {
				log.Printf("[ERROR] Failed to connect to %s: %v", target, err)
			}
		} else {
			defer ls.Close()
			successfulConnection = true
			err = ls.NTLMBind("blah", "blah", "blah")
			if err != nil && strings.Contains(err.Error(), "data 80090346") {
				fmt.Println(colorRed + "	channel binding is enforced on ldaps://" + target + colorReset)
			} else {
				fmt.Println(colorGreen + "	channel binding is NOT enforced, we can relay to ldaps://" + target + colorReset)
				relayLst = append(relayLst, "ldaps://"+target)
			}
		}

		// Add to DC list only if we had at least one successful connection
		if successfulConnection && dcFile != "" {
			dcLst = append(dcLst, target)
		}
	}

	// Write files at the end
	if len(dcLst) > 0 && dcFile != "" {
		err := writeLines(dcLst, dcFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	if len(relayLst) > 0 && relayFile != "" {
		err := writeLines(relayLst, relayFile)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeLines writes the lines to the given file.
func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}
