package main

import (
	"io"
	"log"
	"net"
)

// forwardTLS 把完整 ClientHello 发给目标,然后双向透传。
func forwardTLS(clientConn net.Conn, record []byte, dest, remoteAddr string) {
	destConn, err := net.Dial("tcp", dest)
	if err != nil {
		log.Printf("[%s] 连接目标 %s 失败: %v", remoteAddr, dest, err)
		return
	}
	defer destConn.Close()

	if _, err := destConn.Write(record); err != nil {
		log.Printf("[%s] 转发 ClientHello 失败: %v", remoteAddr, err)
		return
	}

	log.Printf("[%s] 开始双向透传 <-> %s", remoteAddr, dest)
	relay(clientConn, destConn)
}

// forwardRaw 把已读 header 和后续流量原样转发给默认目标。
func forwardRaw(clientConn net.Conn, header []byte, dest string) {
	remoteAddr := clientConn.RemoteAddr().String()
	destConn, err := net.Dial("tcp", dest)
	if err != nil {
		log.Printf("[%s] 连接目标 %s 失败: %v", remoteAddr, dest, err)
		return
	}
	defer destConn.Close()
	if _, err := destConn.Write(header); err != nil {
		log.Printf("[%s] 转发首包失败: %v", remoteAddr, err)
		return
	}
	relay(clientConn, destConn)
}

// relay 双向转发 conn 之间的数据。
func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	<-done
}
