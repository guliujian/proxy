package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"net/http"
	_ "net/http/pprof"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

const SO_ORIGINAL_DST = 80

var (
	serverAddress string
	socks5Address string
	socks5Auth    string
	dialer        proxy.Dialer
)

func init() {
	flag.StringVar(&serverAddress, "l", ":2319", "the server listen address")
	flag.StringVar(&socks5Address, "socks", "192.168.5.13:2080", "the forward socks5 proxy address ")
	flag.StringVar(&socks5Auth, "auth", "", "the socks5 proxy auth example user:test ")
}

func main() {
	// Create a listener
	flag.Parse()
	list, err := net.Listen("tcp", serverAddress)
	if err != nil {
		log.Fatalf("couldn't listen to %q: %q\n", serverAddress, err.Error())
	}
	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	var auth proxy.Auth
	if socks5Auth != "" {
		auth = proxy.Auth{
			User:     strings.Split(socks5Auth, ":")[0],
			Password: strings.Split(socks5Auth, ":")[1],
		}
	} else {
		auth = proxy.Auth{}
	}
	dialer, err = proxy.SOCKS5("tcp", socks5Address, &auth, proxy.Direct)
	if err != nil {
		log.Fatalf("failed to dialer socks5 proxy :%q", err.Error())
	}
	for {
		conn, err := list.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
		}
		go process(conn)
	}
	// defer conn.Close()

	// Print connection details
	// if conn.LocalAddr() == nil {
	// 	log.Fatal("couldn't retrieve local address")
	// }
	// log.Printf("local address: %q", conn.LocalAddr().String())

	// if conn.RemoteAddr() == nil {
	// 	log.Fatal("couldn't retrieve remote address")
	// }
	// log.Printf("remote address: %q", conn.RemoteAddr().String())
}

func process(client net.Conn) {
	if client.LocalAddr() == nil {
		log.Errorf("could not retrieve local address")
		client.Close()
		return
	}
	if client.RemoteAddr() == nil {
		log.Errorf("could not retrieve remote address")
		client.Close()
		return
	}
	log.Printf("local address: %q", client.LocalAddr().String())
	log.Printf("remote address: %q", client.RemoteAddr().String())
	newConn, dst, dport, err := getDestConn(client)
	if err != nil {
		return
	}
	// syscall.SetNonblock(client.(*net.TCPConn).File())
	// client.Close()
	if _, ok := newConn.(*net.TCPConn); ok {
		client = newConn.(*net.TCPConn)
	} else {
		log.Errorf("ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", newConn, newConn)
		return
	}
	log.Printf("dst address: %s:%d", dst, dport)
	target, err := connectDst(dst, dport)
	if err != nil {
		log.Errorf("connect error ", err)
		// fmt.Fprintf(client, "")
		err := client.(*net.TCPConn).SetLinger(0)
		if err != nil {
			log.Errorf("error when setting linger: %s", err)
		}
		client.(*net.TCPConn).Close()
		return
	}
	defer client.Close()
	defer target.Close()
	proxyPack(client, target)

}

func getDestConn(conn net.Conn) (client net.Conn, dst string, dport uint16, err error) {
	tcpConn := conn.(*net.TCPConn)
	tcpConnFile, err := tcpConn.File()
	fd := tcpConnFile.Fd()
	if err != nil {
		log.Error(err)
		tcpConn.Close()
		return nil, "", 0, err
	} else {
		tcpConn.Close()
	}
	addr, err := syscall.GetsockoptIPv6Mreq(int(tcpConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		log.Error(err)
		return nil, "", 0, err
	}
	dst = itod(uint(addr.Multiaddr[4])) + "." +
		itod(uint(addr.Multiaddr[5])) + "." +
		itod(uint(addr.Multiaddr[6])) + "." +
		itod(uint(addr.Multiaddr[7]))
	dport = uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])
	client, err = net.FileConn(tcpConnFile)
	if err != nil {
		log.Error(err)
		return nil, "", 0, err
	}
	syscall.SetNonblock(int(fd), true)
	tcpConnFile.Close()
	return client, dst, dport, nil
}

func connectDst(dst string, dport uint16) (net.Conn, error) {
	// var auth proxy.Auth
	// if socks5Auth != "" {
	// 	auth = proxy.Auth{
	// 		User:     strings.Split(socks5Auth, ":")[0],
	// 		Password: strings.Split(socks5Auth, ":")[1],
	// 	}
	// } else {
	// 	auth = proxy.Auth{}
	// }
	// dialer, err := proxy.SOCKS5("tcp", socks5Address, &auth, proxy.Direct)
	// if err != nil {
	// 	return nil, err
	// }
	// dialer := &net.Dialer{
	// 	Control: func(_, _ string, c syscall.RawConn) error {
	// 		return c.Control(func(fd uintptr) {
	// 			ex := setSocketMark(int(fd), 2515)
	// 			if ex != nil {
	// 				log.Errorf("net dialer set mark error: %s", ex)
	// 			}

	// 		})
	// 	},
	// }
	dstConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%v", dst, dport))
	// dstConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%v", dst, dport))
	return dstConn, err
}

func proxyPack(client, target net.Conn) {
	serverClosed := make(chan struct{}, 1)
	clientClosed := make(chan struct{}, 1)
	// buf := make([]byte, 32*1024)
	go broker(target, client, clientClosed)
	go broker(client, target, serverClosed)

	var waitFor chan struct{}
	select {
	case <-clientClosed:
		// the client closed first and any more packets from the server aren't
		// useful, so we can optionally SetLinger(0) here to recycle the port
		// faster.
		// target.SetLinger(0)
		target.Close()
		waitFor = serverClosed
	case <-serverClosed:
		client.Close()
		waitFor = clientClosed
	}
	<-waitFor

}

func broker(dst, src net.Conn, srcClosed chan struct{}) {
	// buf := make([]byte, 32*1024)
	_, err := io.Copy(dst, src)

	if err != nil {
		log.Printf("Copy error: %s", err)
	}
	if err := src.Close(); err != nil {
		log.Printf("Close error: %s", err)
	}
	srcClosed <- struct{}{}
}

func itod(i uint) string {
	if i == 0 {
		return "0"
	}

	// Assemble decimal in reverse order.
	var b [32]byte
	bp := len(b)
	for ; i > 0; i /= 10 {
		bp--
		b[bp] = byte(i%10) + '0'
	}

	return string(b[bp:])
}

func setSocketMark(fd, mark int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
		return os.NewSyscallError("failed to set mark", err)
	}
	return nil
}
