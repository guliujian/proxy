package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

const SO_ORIGINAL_DST = 80

func main() {
	// Create a listener
	addr := ":2319"
	list, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("couldn't listen to %q: %q\n", addr, err.Error())
	}
	// // Wrap listener in a proxyproto listener
	// proxyListener := &proxyproto.Listener{Listener: list}
	// defer proxyListener.Close()

	// // Wait for a connection and accept it
	// for {
	// 	conn, err := proxyListener.Accept()
	// 	if err != nil {
	// 		log.Printf("Accept failed: %v", err)

	// 	}
	// 	go process(conn)
	// }

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
	tcpConn := client.(*net.TCPConn)
	tcpConnFile, err := tcpConn.File()
	if err != nil {
		log.Error(err)
		tcpConn.Close()
		return
	} else {
		tcpConn.Close()
	}
	addr, err := syscall.GetsockoptIPv6Mreq(int(tcpConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		log.Error(err)
		return
	}
	dst := itod(uint(addr.Multiaddr[4])) + "." +
		itod(uint(addr.Multiaddr[5])) + "." +
		itod(uint(addr.Multiaddr[6])) + "." +
		itod(uint(addr.Multiaddr[7]))
	dport := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])
	newConn, err := net.FileConn(tcpConnFile)
	if err != nil {
		log.Error(err)
		return
	}
	if _, ok := newConn.(*net.TCPConn); ok {
		client = newConn.(*net.TCPConn)
	} else {
		log.Errorf("ERR: newConn is not a *net.TCPConn, instead it is: %T (%v)", newConn, newConn)
		return
	}
	// log.Printf("local address: %q", dst )
	fmt.Println(time.Now())
	log.Printf("address: %s:%s", dst, dport)

	target, err := connectDst(dst, dport)
	if err != nil {
		log.Errorf("connect error ", err)
		client.Write([]byte{})
		client.Close()
		return
	}
	defer target.Close()
	proxyPack(client, target)

}

func connectDst(dst string, dport uint16) (net.Conn, error) {

	dialer, err := proxy.SOCKS5("tcp", "192.168.5.13:2080", nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
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
	buf := make([]byte, 32*1024)
	go broker(target, client, clientClosed, buf)
	go broker(client, target, serverClosed, buf)

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

func broker(dst, src net.Conn, srcClosed chan struct{}, buf []byte) {
	_, err := io.CopyBuffer(dst, src, buf)

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
