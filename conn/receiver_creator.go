package conn

import (
	"net"
	"sync"
)

type ReceiverCreator interface {
	CreateReceiverFn(pc BatchReader, conn *net.UDPConn, rxOffload bool, msgPool *sync.Pool) ReceiveFunc
}
