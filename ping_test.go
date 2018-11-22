package main

import (
	"fmt"
	"testing"
)

func TestRun_tcp_ping(t *testing.T) {
	fmt.Println("start tcp ping")
	var new_pinger Pinger_if
	new_pinger = New_tcp_pinger()
	new_pinger.Set_timeout(1)
	new_pinger.add_p_info("192.168.199.192:9797")
	new_pinger.add_p_info("192.168.199.192:80")
	new_pinger.add_p_info("127.0.0.1:22")
	new_pinger.add_p_info("127.0.0.1:80")
	new_pinger.add_p_info("127.0.0.1:81")
	new_pinger.Run_pinger()
	res := new_pinger.Get_pinger_res()
	fmt.Println("ping test res:", res)
}

func TestRun_icmp_ping(t *testing.T) {
	fmt.Println("start icmp ping")
	var new_pinger Pinger_if
	new_pinger = New_icmp_pinger()
	new_pinger.Set_timeout(3)
	new_pinger.Set_source("192.168.199.202", "")
	new_pinger.add_p_info("192.168.199.192:9797")
	new_pinger.add_p_info("192.168.199.191:9797")
	new_pinger.add_p_info("127.0.0.1:9797")
	new_pinger.Run_pinger()
	res := new_pinger.Get_pinger_res()
	fmt.Println("ping test res:", res)

}
