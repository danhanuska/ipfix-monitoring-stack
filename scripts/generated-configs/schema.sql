CREATE TABLE flows(
    "odid" UInt32, -- maps to the ODID the flow originated from; in 100.00% of records
    "srcip" IPv4, -- in 0.00% of records; alias of iana:sourceIPv4Address
    "dstip" IPv4, -- in 0.00% of records; alias of iana:destinationIPv4Address
    "iana:ipNextHopIPv4Address" IPv4, -- in 0.00% of records
    "iana:ingressInterface" UInt32, -- in 0.00% of records
    "iana:egressInterface" UInt32, -- in 0.00% of records
    "packets" UInt64, -- in 0.00% of records; alias of iana:packetDeltaCount
    "bytes" UInt64, -- in 0.00% of records; alias of iana:octetDeltaCount
    "iana:postPacketDeltaCount" UInt64, -- in 0.00% of records
    "iana:postOctetDeltaCount" UInt64, -- in 0.00% of records
    "flowstart" DateTime64(9), -- in 0.00% of records; alias of iana:flowStartSeconds/iana:flowStartMilliseconds/iana:flowStartMicroseconds/iana:flowStartNanoseconds
    "flowend" DateTime64(9), -- in 0.00% of records; alias of iana:flowEndSeconds/iana:flowEndMilliseconds/iana:flowEndMicroseconds/iana:flowEndNanoseconds
    "srcport" UInt16, -- in 0.00% of records; alias of iana:sourceTransportPort
    "dstport" UInt16, -- in 0.00% of records; alias of iana:destinationTransportPort
    "tcpflags" UInt16, -- in 0.00% of records; alias of iana:tcpControlBits
    "protocol" UInt8, -- in 0.00% of records; alias of iana:protocolIdentifier
    "iana:ipClassOfService" UInt8, -- in 0.00% of records
    "iana:bgpSourceAsNumber" UInt32, -- in 0.00% of records
    "iana:bgpDestinationAsNumber" UInt32, -- in 0.00% of records
    "iana:sourceIPv4PrefixLength" UInt8, -- in 0.00% of records
    "iana:destinationIPv4PrefixLength" UInt8 -- in 0.00% of records
    -- Tip: You may also want to add indexes for better lookup performance
    -- INDEX "srcip_index" "srcip" TYPE bloom_filter GRANULARITY 16,
    -- INDEX "dstip_index" "dstip" TYPE bloom_filter GRANULARITY 16,
)
ENGINE MergeTree
 -- Tip: You may also want to partition and order by flow timestamps
 -- PARTITION BY toStartOfInterval("flowstart", INTERVAL 1 HOUR)
 -- ORDER BY "flowstart"