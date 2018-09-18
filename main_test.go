// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
	"time"
)

func randBase32Bytes(n int) (b []byte) {
	codeMap := []byte("abcdefghijklmnopqrstuvwxyz234567")
	for i := 0; i < n; i++ {
		b = append(b, codeMap[rand.Uint32()%32])
	}
	return b
}

func temp2faFile(data []byte) (*os.File, error) {
	f, err := ioutil.TempFile("", "2fa.*")
	if err != nil {
		return f, err
	}
	_, err = f.Write(data)
	return f, err
}

func TestParseKeychainKeyLine(t *testing.T) {
	k := randBase32Bytes(16)
	line := []byte(fmt.Sprintf("github 6 %s", k))
	fields := parseKeychainKeyLine(line)
	if len(fields) != 3 {
		t.Error("wrong number of fields")
	}
	for i, val := range [][]byte{[]byte("github"), []byte("6"), k} {
		if !bytes.Equal(val, fields[i]) {
			t.Errorf("field %d - Expected: %s, Actual: %s", i, val, fields[i])
		}
	}
}

func TestParseKeychainKeyLineTrailingSpaceCharacters(t *testing.T) {
	k := randBase32Bytes(16)
	line := []byte(fmt.Sprintf("github 6 %s       ", k))
	fields := parseKeychainKeyLine(line)
	if len(fields) != 3 {
		t.Error("wrong number of fields")
	}
	for i, val := range [][]byte{[]byte("github"), []byte("6"), k} {
		if !bytes.Equal(val, fields[i]) {
			t.Errorf("field %d - Expected: %s, Actual: %s", i, val, fields[i])
		}
	}
}

func TestParseKeychainKeyLineTrailingNewlineCharacters(t *testing.T) {
	k := randBase32Bytes(16)
	line := []byte(fmt.Sprintf("github 6 %s\n\n\n\n", k))
	fields := parseKeychainKeyLine(line)
	if len(fields) != 3 {
		t.Error("wrong number of fields")
	}
	for i, val := range [][]byte{[]byte("github"), []byte("6"), k} {
		if !bytes.Equal(val, fields[i]) {
			t.Errorf("field %d - Expected: %s, Actual: %s", i, val, fields[i])
		}
	}
}

func TestParseKeychainKeyLineTrailingNewlineAndSpaceCharacters(t *testing.T) {
	k := randBase32Bytes(16)
	line := []byte(fmt.Sprintf("github 6 %s\n \n  \n ", k))
	fields := parseKeychainKeyLine(line)
	if len(fields) != 3 {
		t.Error("wrong number of fields")
	}
	for i, val := range [][]byte{[]byte("github"), []byte("6"), k} {
		if !bytes.Equal(val, fields[i]) {
			t.Errorf("field %d - Expected: %s, Actual: %s", i, val, fields[i])
		}
	}
}

func TestParseKeychainKeys(t *testing.T) {
	githubKey := randBase32Bytes(16)
	googleKey := randBase32Bytes(16)
	keychainBytes := []byte(fmt.Sprintf("github 6 %s\ngoogle 6 %s", githubKey, googleKey))
	keys := parseKeychainKeys(keychainBytes)
	for _, k := range []string{"github", "google"} {
		if key, ok := keys[k]; ok {
			if key.digits != 6 {
				t.Error("wrong digits count for key:", k)
			}
		} else {
			t.Error("key not found:", k)
		}
	}
}

func TestParseKeychainKeysTrailingSpaceCharacters(t *testing.T) {
	githubKey := randBase32Bytes(16)
	googleKey := randBase32Bytes(16)
	keychainBytes := []byte(fmt.Sprintf("github 6 %s  \ngoogle 6 %s     ", githubKey, googleKey))
	keys := parseKeychainKeys(keychainBytes)
	for _, k := range []string{"github", "google"} {
		if key, ok := keys[k]; ok {
			if key.digits != 6 {
				t.Error("wrong digits count for key:", k)
			}
		} else {
			t.Error("key not found:", k)
		}
	}
}

func TestParseKeychainKeysTrailingNewlineCharacters(t *testing.T) {
	githubKey := randBase32Bytes(16)
	googleKey := randBase32Bytes(16)
	keychainBytes := []byte(fmt.Sprintf("github 6 %s\n\n\n\n\ngoogle 6 %s\n\n\n", githubKey, googleKey))
	keys := parseKeychainKeys(keychainBytes)
	for _, k := range []string{"github", "google"} {
		if key, ok := keys[k]; ok {
			if key.digits != 6 {
				t.Error("wrong digits count for key:", k)
			}
		} else {
			t.Error("key not found:", k)
		}
	}
}

func TestParseKeychainKeysTrailingNewlineAndSpaceCharacters(t *testing.T) {
	githubKey := randBase32Bytes(16)
	googleKey := randBase32Bytes(16)
	keychainBytes := []byte(fmt.Sprintf("github 6 %s\n\n   \n    \n\ngoogle 6 %s  \n\n \n", githubKey, googleKey))
	keys := parseKeychainKeys(keychainBytes)
	for _, k := range []string{"github", "google"} {
		if key, ok := keys[k]; ok {
			if key.digits != 6 {
				t.Error("wrong digits count for key:", k)
			}
		} else {
			t.Error("key not found:", k)
		}
	}
}

func mockHotp(key []byte, counter uint64, digits int) int {
	return hotp(key, 0, digits)
}

func mockTotp(key []byte, t time.Time, digits int) int {
	return hotp(key, 0, digits)
}

func TestKeychainCodeTotp(t *testing.T) {
	keychainBytes := []byte("github 6 abcdef23ghijkl45\ngoogle 6 mnopqr67stuvwx23")
	file, err := temp2faFile(keychainBytes)
	if err != nil {
		t.Error(err)
	}
	keychain := newKeychain(file.Name(), keychainBytes)
	keychain.Hotp = mockHotp
	keychain.Totp = mockTotp
	for k, v := range map[string]string{"github": "149042", "google": "561295"} {
		code := keychain.code(k)
		if code != v {
			t.Errorf("incorrect code - Key: %s, Expected %s, Actual %s", k, v, code)
		}
	}
}
