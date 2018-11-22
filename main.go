package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	// "golang.org/x/net/ipv4"
	// "golang.org/x/net/ipv6"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	Ping_unknown = 0
	Ping_OK      = 1
	Ping_timeout = 2
	Ping_noconn  = 3
)

type ping_res_s struct {
	ipaddr   string
	ping_res int
}

type Pinger_if interface {
	Set_timeout(timeout time.Duration)
	add_p_info(ip_str string)
	Set_source(source string, source6 string)
	Run_pinger()
	Get_pinger_res() map[string]int
	Stop_pinger()
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

func regist_helper(host, dev_type, user, password string) bool {
	resp, err := http.PostForm(host, url.Values{"dev_type": {dev_type}, "user": {user}, "password": {password}})
	if err != nil {
		fmt.Println("registed fail")
		return false
	}
	resp.Body.Close()
	fmt.Println("registed ok")
	return true
}

func server_handler(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("recv ok!\n"))
	body, _ := ioutil.ReadAll(req.Body)
	defer req.Body.Close()
	body_str := string(body)
	fmt.Println("body:", body_str)
	var dat map[string]interface{}
	if err := json.Unmarshal(body, &dat); err == nil {
		if v, ok := dat["ip_list"]; ok {
			if check_ip_list, ok := v.(string); ok {
				if len(check_ip_list) > 0 {
					fmt.Println(check_ip_list)
					listen_chan <- check_ip_list
				}
			}
		}
	} else {
		fmt.Println(err)
	}
}

func listen_helper(port string) {
	http.HandleFunc("/ip_list", server_handler)
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		fmt.Println("ListenAndServe: ", err)
		panic(err)
	}
}

func post_res_helper(ping_reses []map[string]int) {

}

var listen_chan chan string

func main() {
	listen_chan = make(chan string)
	for {
		if ok := regist_helper("http://192.168.199.192:6565/reg", "pinger_type", "user", "password"); ok {
			break
		}
		time.Sleep(3 * time.Second)
	}

	go listen_helper("6565")
	var check_ip_string string
	for {
		check_ip_string = <-listen_chan
		go func(check_ip_string string) {
			fmt.Println("start pinger")
			check_ip_list := strings.Split(check_ip_string, ",")
			var ping_reses []map[string]int = make([]map[string]int, 2)
			wg := new(sync.WaitGroup)
			var i int
			for i = 0; i < 2; i++ {
				wg.Add(1)
				ping_reses[i] = make(map[string]int)
				go func(check_ip_list []string, i int) {
					var new_pinger Pinger_if
					if i == 0 {
						fmt.Println("start tcp ping")
						new_pinger = New_tcp_pinger()
					} else {
						fmt.Println("start icmp ping")
						new_pinger = New_icmp_pinger()
						new_pinger.Set_source("192.168.199.202", "")
					}
					new_pinger.Set_timeout(5)
					for _, addr := range check_ip_list {
						new_pinger.add_p_info(addr)
					}
					new_pinger.Run_pinger()
					ping_reses[i] = new_pinger.Get_pinger_res()
					fmt.Println("ping test res:", ping_reses[i])
					wg.Done()
				}(check_ip_list, i)
			}
			wg.Wait()
			post_res_helper(ping_reses)
		}(check_ip_string)
	}
}
