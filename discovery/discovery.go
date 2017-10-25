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

package discovery

import (
	"encoding/csv"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/temorfeouz/go-wifi/AP"
)

// WARNING in order to use airodump-ng, you may need root access

// JSON exportable structs
// Full discovery
type Discovery struct {
	APs     []*AP.AP    `json:"aps"`
	Clients []AP.Client `json:"clients"`
	Running bool        `json:"running"`
	Started string      `json:"started at"`
	Stopped string      `json:"stopped at"`
	process *os.Process
}

func (d *Discovery) FindWifiMACByName(wifiName string) string {
	for _, ap := range d.APs {
		if ap.Essid == wifiName {
			return ap.Bssid
		}
	}
	return ""
}

// Stop the discovery...
func (d *Discovery) Stop() error {
	err := d.process.Kill()
	if err != nil {
		return err
	}

	d.Running = false
	d.Stopped = time.Now().String()

	return nil
}

func (d *Discovery) GetAP() *AP.AP {
	for _, elem := range d.APs {
		if elem.IsSniff == false && elem.Essid == "homeNet" {
			return elem
		}
	}
	return nil
}

// TODO: use a netxml parser

// THE most important function: parse /tmp/discovery-01.csv and fill the structs
// Might be nice to run as a goroutine...
// IDEA: parallelise the parsing with 2 goroutines
func (d *Discovery) Parse() error {
	// Dirty hack to have a clean dump
	logFile := os.TempDir() + "/discovery-01.csv"
	var _, err = os.Stat(logFile)

	// create file if not exists
	if os.IsNotExist(err) {
		log.Printf("wait %s file...", logFile)
		return nil
	}
	dump, err := ioutil.ReadFile(logFile)
	if err != nil {
		return err
	}

	if len(dump) == 0 {
		return nil
	}

	dump_str := string(dump)
	// Replace endline with just an  \n
	dump_str = strings.Replace(dump_str, ", \r\n", ", \n", -1)
	dump_str = strings.Replace(dump_str, ",\r\n", ",\n", -1)
	dump_split := strings.SplitN(dump_str, "\r\n", 4)

	// Extract the two parts of the csv
	dump_aps := dump_split[2]
	dump_clients := dump_split[3]
	dump_clients = strings.SplitN(dump_clients, "\r\n", 2)[1]

	// End of dirty hack, fill the structs
	reader_aps := csv.NewReader(strings.NewReader(dump_aps))
	reader_clients := csv.NewReader(strings.NewReader(dump_clients))

	// We will fill them back later
	//	d.APs = nil
	//	d.Clients = nil

	// Start with the aps
	for {
		record, csv_err := reader_aps.Read()
		if csv_err == io.EOF {
			break
		}
		if csv_err != nil {
			return err
		}

		// Okay, fill an AP struct then append to the dump

		// TODO: clean that
		// NOTE: I am too lazy to check the errors
		channel := strToInt(record[3])
		speed := strToInt(record[4])
		power := strToInt(record[8])
		beacons := strToInt(record[9])
		ivs := strToInt(record[10])
		idlen := strToInt(record[12])

		cur_ap := AP.AP{
			Bssid:   strings.TrimSpace(record[0]),
			First:   strings.TrimSpace(record[1]),
			Last:    strings.TrimSpace(record[2]),
			Channel: channel,
			Speed:   speed,
			Privacy: strings.TrimSpace(record[5]),
			Cipher:  strings.TrimSpace(record[6]),
			Auth:    strings.TrimSpace(record[7]),
			Power:   power,
			Beacons: beacons,
			IVs:     ivs,
			Lan:     strings.TrimSpace(record[11]),
			IdLen:   idlen,
			Essid:   strings.TrimSpace(record[13]),
			Key:     strings.TrimSpace(record[14]),
		}

		needAddAP := true
		for _, ap := range d.APs {
			if ap.Essid == cur_ap.Essid {
				needAddAP = false
				break
			}
		}
		if needAddAP {
			d.APs = append(d.APs, &cur_ap)
		}
	}

	// Continue with the clients
	for {
		record, csv_err := reader_clients.Read()
		if csv_err == io.EOF {
			break
		}
		if csv_err != nil {
			return err
		}

		// Okay, fill a Client struct then append to the dump

		// TODO: clean that
		// NOTE: too lazy to fix the errors
		power, _ := strconv.Atoi(record[3])
		packets, _ := strconv.Atoi(record[4])

		cur_client := AP.Client{
			Station: strings.TrimSpace(record[0]),
			First:   strings.TrimSpace(record[1]),
			Last:    strings.TrimSpace(record[2]),
			Power:   power,
			Packets: packets,
			Bssid:   strings.TrimSpace(record[5]),
			Probed:  strings.TrimSpace(record[6]),
		}

		isNeedAddClient := true
		for _, client := range d.Clients {
			if client.Bssid == cur_client.Bssid {
				isNeedAddClient = false
				break
			}
		}

		if isNeedAddClient {
			d.Clients = append(d.Clients, cur_client)
		}
	}

	return nil
}
func strToInt(s string) int {
	toReturn, err := strconv.Atoi(strings.TrimSpace(s))
	if nil != err {
		panic(err)
	}

	return toReturn
}

// Start a new discovery thanks to airodump-ng
// iface MUST be the name of valid monitor mode iface
// it will create a temp file named "discovery-01.csv", if it exist,
// it will be deleted!
// Return a Discovery object
func StartDiscovery(iface string) (Discovery, error) {
	pathToOut := os.TempDir() + "/discovery"
	// Delete previous log file
	exec.Command("rm", "-rf", pathToOut+"*").Output()

	// okay, enough cosmetics, time for real code!
	cmd := exec.Command("airodump-ng", "--write", pathToOut, "--output-format", "csv", iface)

	err := cmd.Start() // Do not wait

	discovery := Discovery{
		Started: time.Now().String(),
		Running: false,
	}

	if err == nil {
		discovery.Running = true
		discovery.process = cmd.Process
	}

	return discovery, err
}
