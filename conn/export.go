package conn

const (
	UdpSegmentMaxDatagrams = udpSegmentMaxDatagrams
)

var (
	SplitCoalescedMessages = splitCoalescedMessages
	GetSrcFromControl      = getSrcFromControl

	GetGSOSize = getGSOSize

	// DisableUDPGRO is for binds that build their own receive functions on top of
	// StdNetBind and read batches smaller than IdealBatchSize; see rxOffloadFor.
	DisableUDPGRO = disableUDPGRO

	// export controlFns for Android to use
	// is not thread safe and should only be modified during init.
	ControlFns = &controlFns
)

type BatchReader = batchReader
