package main

import (
	"fmt"
	"net"
	"sync"
	"time"
	"strings"
)

type tcp_ping_info struct {
	addr      string
	port      string
	ping_res  int
	send_time time.Time
	info_lock sync.Mutex
}

type Tcp_pinger struct {
	p_info_map map[string]*tcp_ping_info
	timeout    time.Duration
	stop       chan bool
}

func New_tcp_pinger() Pinger_if {
	return &Tcp_pinger{
		p_info_map: make(map[string]*tcp_ping_info),
		timeout:    10,
		stop:       make(chan bool),
	}
}
func (pinger *Tcp_pinger) Stop_pinger(){
	return
}
func (pinger *Tcp_pinger) Set_source(source string, source6 string) {
	return
}
func (pinger *Tcp_pinger) Set_timeout(timeout time.Duration) {
	pinger.timeout = timeout * time.Second
}

func (pinger *Tcp_pinger) add_p_info(ip_str string) {
	ip_str_list := strings.Split(ip_str, ":")
	if len(ip_str_list)<2{
		fmt.Println("ip str error")
		return 
	}
	addr := net.ParseIP(ip_str_list[0])
	if addr == nil {
		fmt.Println(ip_str + " is not a valid textual representation of an IPv4/IPv6 address")
		return 
	}	
	new_ping_info :=
		&tcp_ping_info{
			addr:      ip_str_list[0],
			port:      ip_str_list[1],
			ping_res:  Ping_unknown,
			send_time: time.Now(),
		}
	pinger.p_info_map[ip_str] = new_ping_info
}

func (pinger *Tcp_pinger) Run_pinger() {
	var network string
	var Conn net.Conn
	var err error
	wg := new(sync.WaitGroup)
	for _, p_info := range pinger.p_info_map {
		wg.Add(1)
		go func(p_info *tcp_ping_info) {
			defer wg.Done()
			tmp_IP := net.ParseIP(p_info.addr)
			if isIPv4(tmp_IP) {
				network = "tcp"
			} else if isIPv6(tmp_IP) {
				network = "tcp6"
			} else {
				fmt.Println(p_info.addr + ":" + p_info.port + " is not a valid textual representation of an IPv4/6 address")
				return
			}
			if Conn, err = net.DialTimeout(network, p_info.addr+":"+p_info.port, pinger.timeout); err != nil {
				if neterr, ok := err.(net.Error); ok {
					if neterr.Timeout() {
						p_info.ping_res = Ping_timeout
						return
					}
					// if neterr.Temporary() {
					// 	fmt.Println("Temporary err", err)
					// 	return
					// }
				}
				// fmt.Println("Dial err: ", err)
				return
			}
			defer Conn.Close()
			p_info.ping_res = Ping_OK
		}(p_info)

	}
	wg.Wait()
}

func (pinger *Tcp_pinger) Get_pinger_res() map[string]int  {	
	var res map[string]int = make(map[string]int)
	for key, p_info := range pinger.p_info_map {
		res[key] = p_info.ping_res
	}
	return res
}
