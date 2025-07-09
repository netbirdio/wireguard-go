package conn

import (
	"net"
	"sync"

	"golang.org/x/net/ipv6"
)

// PacketReader abstracts ipv4.PacketConn and ipv6.PacketConn which both implement ReadBatch
type PacketReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type ReceiverCreator interface {
	CreateReceiverFn(pc PacketReader, conn *net.UDPConn, rxOffload bool, msgPool *sync.Pool) ReceiveFunc
}
