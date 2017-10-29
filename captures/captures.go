/*

   Copyright (C) 2016  DeveloppSoft <developpsoft@gmail.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

*/

package captures

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Capture struct: handle airodump captures to crack them with aircrack-ng
type (
	Capture struct {
		Key       string `json:"key"`
		Target    Target `json:"target"`
		Handshake bool   `json:"handshake captured"`
		IVs       int    `json:"ivs"`
		Cracking  bool   `json:"trying to crack"`
		pcap_file string
	}

	Target struct {
		Bssid string `json:"bssid"`
		Essid string `json:"essid"`
		// WPA, WPA2, WEP, OPN
		Privacy string `json:"privacy"`
	}
)

// Build the struct thanks to the dir (with .pcap and .csv) path
func (c *Capture) Init(path_to_captures string, privacy string, bssid string, essid string) {
	c.pcap_file = path_to_captures + "/*.cap"

	// Fill the struct!
	c.Target.Bssid = bssid
	c.Target.Essid = essid
	c.Target.Privacy = privacy

	// Check if we have an Handshake
	if privacy == "WPA" || privacy == "WPA2" {
		c.СheckForHandshake()
	}

	c.getIVs()
}

// Return succesfull key
func (c *Capture) TryKeys(keys ...string) string {
	if c.Target.Privacy == "WEP" || c.Target.Privacy == "OPN" {
		// Only wpa
		return ""
	}

	// build a temp dict
	path := os.TempDir() + "go-wifi-tmp-dict"

	file, err := os.Create(path)
	if err != nil {
		// Got an error, exit
		return ""
	}
	defer file.Close()
	defer os.Remove(path)

	for _, key := range keys {
		file.WriteString(key + "\n")
	}

	return c.crackWPA(path)
}

// Return ascii key; if cracking WEP dict can be null
func (c *Capture) AttemptToCrack(dict string) string {
	// Do not crack a second time!
	// if c.Key != "" {
	// 	return c.Key
	// }

	// Start here
	var key string

	if (strings.Contains(c.Target.Privacy, "WPA")) && dict != "" {
		key = c.crackWPA(dict)
	} else if c.Target.Privacy == "WEP" {
		key = c.crackWEP()
	} else {
		key = ""
	}

	if key != "" {
		c.Key = key
	}

	return key
}

func (c *Capture) crackWPA(dict string) string {
	pathToKey := os.TempDir() + "/go-wifi-key-" + c.Target.Essid

	// If the file exist, delete it
	os.Remove(pathToKey)
	commandArgs := fmt.Sprintf(`aircrack-ng -a 2 -l %s -w %s -b %s %s`, pathToKey, dict, c.Target.Bssid, c.pcap_file)
	cmd := exec.Command("sh", "-c", commandArgs)
	//log.Println("sh", "-c", commandArgs)
	// cmd := exec.Command("aircrack-ng", "-a", "2", "-l", path_to_key, "-w", dict, "-b", c.Target.Bssid, c.pcap_file)
	cmd.Run()

	// Wait termination so we can get the key
	cmd.Wait()

	key_buf, err := ioutil.ReadFile(pathToKey)
	if err != nil {
		// no key found
		return ""
	}

	return string(key_buf)
}

func (c *Capture) crackWEP() string {
	// Start with PTW
	// I use a random file so you can run the func in parallel
	path_to_key := os.TempDir() + "go-wifi_key" + strconv.Itoa(rand.Int())

	// If the file exist, delete it
	os.Remove(path_to_key)

	cmd := exec.Command("aircrack-ng", "-D", "-z", "-a", "1", "-l", path_to_key, "-b", c.Target.Bssid, c.pcap_file)
	cmd.Run()

	// Wait termination so we can get the key
	cmd.Wait()

	// Check if we succeed
	key_buf, err := ioutil.ReadFile(path_to_key)
	if err != nil {
		// no key found, start Korek
		cmd = exec.Command("aircrack-ng", "-D", "-K", "-a", "1", "-l", path_to_key, "-b", c.Target.Bssid, c.pcap_file)
		cmd.Run()
		cmd.Wait()

		key_buf, err = ioutil.ReadFile(path_to_key)
		if err != nil {
			// Korek and PTW failed, exit
			return ""
		}
	}

	// key_buf has a key!
	return string(key_buf)
}

func (c *Capture) СheckForHandshake() {
	// Thank you wifite (l. 2478, has_handshake_aircrack)
	// build a temp dict
	path := os.TempDir() + "/go-wifi-fake-dict"
	outputFile := os.TempDir() + "/tmpoutput" + c.Target.Essid

	file, err := os.Create(path)
	if err != nil {
		// Got an error, exit
		return
	}
	defer file.Close()

	file.WriteString("that_is_a_fake_key_no_one_will_use")

	commandArgs := fmt.Sprintf(` aircrack-ng -w %s -b %s %s > %s`, path, c.Target.Bssid, c.pcap_file, outputFile)
	cmd := exec.Command("sh", "-c", commandArgs)
	cmd.Output()

	// here read file and analuze it
	output, err := ioutil.ReadFile(outputFile)

	if strings.Contains(string(output), "Passphrase not in dictionary") {
		c.Handshake = true
	} else {
		c.Handshake = false
	}
	// Delete file
	// os.Remove(path)
}

func (c *Capture) getIVs() {
	// TODO: count ivs!
	c.IVs = 0
}
