package main

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ProtocolICMP     = 1
	ProtocolIPv6ICMP = 58
)

type packet struct {
	bytes []byte
	addr  net.Addr
}

type ping_info struct {
	addr      string
	port      string
	is_ipv4   bool
	is_ipv6   bool
	ping_res  int
	send_time time.Time
	info_lock sync.Mutex
}

type Icmp_pinger struct {
	id            int
	seq           int
	source        string
	source6       string
	p_info_map    map[string]*ping_info
	conn          *icmp.PacketConn
	conn6         *icmp.PacketConn
	has_4         bool
	has_6         bool
	timeout       time.Duration
	stop          chan bool
	send_done     chan bool
	process_start chan bool
	process_done  chan bool
	recv_buf_chan chan *packet
}

func New_icmp_pinger() Pinger_if {
	rand.Seed(time.Now().UnixNano())
	return &Icmp_pinger{
		id:            rand.Intn(0xffff),
		seq:           rand.Intn(0xffff),
		source:        "",
		source6:       "",
		p_info_map:    make(map[string]*ping_info),
		conn:          nil,
		conn6:         nil,
		has_4:         false,
		has_6:         false,
		timeout:       1 * time.Second,
		stop:          make(chan bool),
		send_done:     make(chan bool),
		process_start: make(chan bool, 100),
		process_done:  make(chan bool, 100),
		recv_buf_chan: make(chan *packet, 100),
	}
}

func (pinger *Icmp_pinger) add_p_info(ip_str string) {
	ip_str_without_port, ip_port := strings.Split(ip_str, ":")[0], strings.Split(ip_str, ":")[1]
	addr := net.ParseIP(ip_str_without_port)
	if addr == nil {
		fmt.Println(ip_str + " is not a valid textual representation of an IPv4/IPv6 address")
	}
	// //fmt.Println("real icmp ping address:", ip_str_without_port)
	if pinger.p_info_map[ip_str_without_port] != nil {
		pinger.p_info_map[ip_str_without_port].port = pinger.p_info_map[ip_str_without_port].port + "," + ip_port
		return
	}
	new_ping_info := &ping_info{
		addr:     ip_str_without_port,
		is_ipv4:  false,
		is_ipv6:  false,
		ping_res: Ping_unknown,
		port:     ip_port,
	}
	if isIPv4(addr) {
		new_ping_info.is_ipv4 = true
	} else if isIPv6(addr) {
		new_ping_info.is_ipv6 = true
	}
	pinger.p_info_map[ip_str_without_port] = new_ping_info
}

func (pinger *Icmp_pinger) Set_timeout(timeout time.Duration) {
	pinger.timeout = timeout * time.Second
}

func (pinger *Icmp_pinger) Set_source(source string, source6 string) {
	if source == "" && source6 == "" {
		panic("ip address is None")

	}
	if source != "" {
		addr := net.ParseIP(source)
		if addr == nil || isIPv4(addr) == false {
			panic(source + " is not a valid textual representation of an IPv4 address")
		}
		pinger.source = source
	}
	if source6 != "" {
		addr := net.ParseIP(source6)
		if addr == nil || isIPv4(addr) == false {
			panic(source + " is not a valid textual representation of an IPv6 address")
		}
		pinger.source6 = source6
	}
}

func (pinger *Icmp_pinger) Stop_pinger() {
	pinger.stop <- true
}

func (pinger *Icmp_pinger) listen() {
	var network string
	if pinger.source != "" {
		network = "ip4:icmp"
		conn, err := icmp.ListenPacket(network, pinger.source)
		if err != nil {
			fmt.Printf("Error listening for ICMP packets: %s\n", err.Error())
			panic(err)
		}
		pinger.conn = conn
		pinger.has_4 = true
	}
	if pinger.source6 != "" {
		network = "ip6:ipv6-icmp"
		conn, err := icmp.ListenPacket(network, pinger.source6)
		if err != nil {
			fmt.Printf("Error listening for ICMP packets: %s\n", err.Error())
			panic(err)
		}
		pinger.conn6 = conn
		pinger.has_6 = true
	}
}

func (pinger *Icmp_pinger) sendICMP() {
	pinger.id = rand.Intn(0xffff)
	pinger.seq = rand.Intn(0xffff)
	var typ icmp.Type
	var dst net.Addr
	var bytes []byte
	var err error
	wg := new(sync.WaitGroup)
	var cn *icmp.PacketConn = nil
	for key, p_info := range pinger.p_info_map {
		if p_info.is_ipv4 && pinger.has_4 == true {
			typ = ipv4.ICMPTypeEcho
			cn = pinger.conn
		}
		if p_info.is_ipv6 && pinger.has_6 == true {
			typ = ipv6.ICMPTypeEchoRequest
			cn = pinger.conn6
		}
		if cn == nil {
			p_info.ping_res = Ping_noconn
			fmt.Println("no cn", pinger.p_info_map[key])
			continue
		}

		bytes, err = (&icmp.Message{
			Type: typ, Code: 0,
			Body: &icmp.Echo{
				ID: pinger.id, Seq: pinger.seq,
				Data: []byte{0, 0, 0, 0, 0, 0, 0, 0},
			},
		}).Marshal(nil)
		if err != nil {
			fmt.Println(err)
			continue
		}
		dst = &net.IPAddr{IP: net.ParseIP(p_info.addr)}
		// //fmt.Println("send ip ", dst)
		// //fmt.Println(bytes)
		wg.Add(1)
		go func(conn *icmp.PacketConn, dst net.Addr, bytes []byte, p_info_map map[string]*ping_info, key string) {
			for {
				if _, err := conn.WriteTo(bytes, dst); err != nil {
					if neterr, ok := err.(*net.OpError); ok {
						if neterr.Err == syscall.ENOBUFS {
							continue
						}
					}
					fmt.Println("send error:", err)
				}
				break
			}
			p_info_map[key].send_time = time.Now()
			wg.Done()
		}(cn, dst, bytes, pinger.p_info_map, key)
		// //fmt.Println("--------", p_info.send_time)
	}
	wg.Wait()
	pinger.send_done <- true
	// //fmt.Println("send done")
}

func (pinger *Icmp_pinger) recvICMP() {
	for {
		select {
		case <-pinger.stop:
			//fmt.Println("recv done")
			return
		default:
		}
		bytes := make([]byte, 512)
		pinger.conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
		_, ra, err := pinger.conn.ReadFrom(bytes)
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Timeout() {
					continue
				} else {
					fmt.Println(err)
					return
				}
			}
		}
		//fmt.Println("recv packet:", ra)
		pinger.recv_buf_chan <- &packet{bytes: bytes, addr: ra}
	}
}

func (pinger *Icmp_pinger) process_package(recv_packet *packet) {
	var ipaddr *net.IPAddr
	var msg *icmp.Message
	var err error
	var bytes []byte
	var proto int
	//fmt.Println("start process packet")
	pinger.process_start <- true
	defer func() {
		if err != nil {
			fmt.Println(err)
		}
		pinger.process_done <- true

	}()
	if tmp_ipaddr, ok := recv_packet.addr.(*net.IPAddr); ok {
		ipaddr = tmp_ipaddr
	} else {
		fmt.Println("ipaddr type assertion fail")
		return
	}

	if isIPv4(ipaddr.IP) {
		proto = ProtocolICMP
	} else if isIPv6(ipaddr.IP) {
		proto = ProtocolIPv6ICMP
	}
	bytes = recv_packet.bytes

	if msg, err = icmp.ParseMessage(proto, bytes); err != nil {
		return
	}
	if msg.Type != ipv4.ICMPTypeEchoReply && msg.Type != ipv6.ICMPTypeEchoReply {
		return
	}
	switch pkt := msg.Body.(type) {
	case *icmp.Echo:
		if pkt.ID == pinger.id && pkt.Seq == pinger.seq {
			key := ipaddr.String()
			pinger.p_info_map[key].info_lock.Lock()
			pinger.p_info_map[key].ping_res = Ping_OK
			pinger.p_info_map[key].info_lock.Unlock()
			//fmt.Println("ping ok :", key)
			return
		}
	default:
		return
	}

}

func (pinger *Icmp_pinger) Run_pinger() {
	pinger.listen()
	defer pinger.conn.Close()
	defer pinger.conn6.Close()
	go pinger.sendICMP()
	go pinger.recvICMP()
	// send_done := false
	//fmt.Println(pinger.timeout)
Runloop:
	for {
		select {
		case recv_packet := <-pinger.recv_buf_chan:
			go pinger.process_package(recv_packet)

		//after processed a packet, try to receive a new packet
		case <-pinger.process_start:
			<-pinger.process_done
			//fmt.Println("process_done 1")
		case _, ok := <-pinger.send_done:
			if ok {
				//fmt.Println("close send done")
				close(pinger.send_done)
				ticker := time.NewTicker(2 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case recv_packet := <-pinger.recv_buf_chan:
						go pinger.process_package(recv_packet)

					//after processed a packet, try to receive a new packet
					case <-pinger.process_start:
						<-pinger.process_done
						//fmt.Println("process_done 2")
					default:
					}
					select {
					case <-ticker.C:
						//fmt.Println("time out")
					subloop1:
						for {
							select {
							case <-pinger.process_start:
								<-pinger.process_done
								//fmt.Println("process_done 3")
							default:
								//fmt.Println("leave subloop1")
								break subloop1
							}
						}
						for _, p_info := range pinger.p_info_map {
							if p_info.ping_res == Ping_unknown && !p_info.send_time.IsZero() {
								p_info.info_lock.Lock()
								p_info.ping_res = Ping_timeout
								p_info.info_lock.Unlock()
							}
						}
						break Runloop
					default:
					}
				}

			} else {
				fmt.Println("send done close no reason")
				break Runloop
			}
		}
	}
	pinger.stop <- true
	//fmt.Println("leave mainloop")
}
func (pinger *Icmp_pinger) Get_pinger_res() map[string]int {
	var res map[string]int = make(map[string]int)
	for key, p_info := range pinger.p_info_map {
		for _, i_port := range strings.Split(p_info.port, ",") {
			res[key+":"+i_port] = p_info.ping_res
		}
	}
	return res
}
