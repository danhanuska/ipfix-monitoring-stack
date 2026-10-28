--Databases
CREATE DATABASE IF NOT EXISTS net_monitor;

--Main tables
CREATE TABLE IF NOT EXISTS net_monitor.flows_raw
(
    `vlanId` UInt16,
    `srcMacAddress` UInt64,
    `srcip` IPv6,
    `dstip` IPv6,
    `srcport` UInt16,
    `dstport` UInt16,
    `tcpflags` UInt16,
    `bytes` UInt64,
    `packets` UInt64,
    `flowstart` DateTime64(9),
    `flowend` DateTime64(9),
    `ipClassOfService` UInt8,
    `protocol` UInt8
)
ENGINE = Null;


CREATE TABLE IF NOT EXISTS net_monitor.flows
(
    `device` LowCardinality(String) CODEC(ZSTD(1)),
    `vlanId` UInt16 CODEC(T64, ZSTD(1)),
    `srcMacAddress` UInt64 CODEC(T64, ZSTD(1)),
    `srcip` IPv6 CODEC(ZSTD(1)),
    `dstip` IPv6 CODEC(ZSTD(1)),
    `srcport` UInt16 CODEC(T64, ZSTD(1)),
    `dstport` UInt16 CODEC(T64, ZSTD(1)),
    `tcpflags` UInt16 CODEC(T64, ZSTD(1)),
    `tcpflags_str` String CODEC(ZSTD(1)),
    `bytes` UInt64 CODEC(T64, ZSTD(1)),
    `packets` UInt64 CODEC(T64, ZSTD(1)),
    `flowstart` DateTime CODEC(Delta(4), ZSTD(1)),
    `flowend` DateTime CODEC(Delta(4), ZSTD(1)),
    `ipClassOfService` UInt8 CODEC(T64, ZSTD(1)),
    `priority` String CODEC(ZSTD(1)),
    `ecn` String CODEC(ZSTD(1)),
    `protocol` UInt8 CODEC(T64, ZSTD(1)),
    `protocol_name` String CODEC(ZSTD(1)),
    `direction` LowCardinality(String) CODEC(ZSTD(1)),
    `is_internal` UInt8 CODEC(T64, ZSTD(1)),
    PROJECTION p_ip_analysis
    (
        SELECT * ORDER BY srcip, dstip, flowstart
    )
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(flowstart)
ORDER BY (flowstart, device, srcip, dstip)
TTL flowstart + toIntervalMonth(3)
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1;

--Source tables for dictionaries
CREATE TABLE IF NOT EXISTS net_monitor.protocol_source
(
    `id` UInt8,
    `label` String
)
ENGINE = MergeTree
ORDER BY id;

TRUNCATE TABLE net_monitor.protocol_source;
INSERT INTO net_monitor.protocol_source VALUES
    (0, 'HOPOPT'), (1, 'ICMP'), (2, 'IGMP'), (3, 'GGP'), (4, 'IP-in-IP'), (5, 'ST'), (6, 'TCP'), (7, 'CBT'), (8, 'EGP'), (9, 'IGP'), (10, 'BBN-RCC-MON'), (11, 'NVP-II'), (12, 'PUP'), (13, 'ARGUS'), (14, 'EMCON'), (15, 'XNET'), (16, 'CHAOS'), (17, 'UDP'), (18, 'MUX'), (19, 'DCN-MEAS'), (20, 'HMP'), (21, 'PRM'), (22, 'XNS-IDP'), (23, 'TRUNK-1'), (24, 'TRUNK-2'), (25, 'LEAF-1'), (26, 'LEAF-2'), (27, 'RDP'), (28, 'IRTP'), (29, 'ISO-TP4'), (30, 'NETBLT'), (31, 'MFE-NSP'), (32, 'MERIT-INP'), (33, 'DCCP'), (34, '3PC'),  (35, 'IDPR'), (36, 'XTP'), (37, 'DDP'), (38, 'IDPR-CMTP'), (39, 'TP++'), (40, 'IL'), (41, 'IPv6'), (42, 'SDRP'), (43, 'IPv6-Route'), (44, 'IPv6-Frag'), (45, 'IDRP'), (46, 'RSVP'), (47, 'GRE'), (48, 'DSR'), (49, 'BNA'), (50, 'ESP'), (51, 'AH'), (52, 'I-NLSP'), (53, 'SwIPe'), (54, 'NARP'), (55, 'MOBILE'), (56, 'TLSP'), (57, 'SKIP'), (58, 'ICMPv6'), (59, 'IPv6-NoNxt'), (60, 'IPv6-Opts'), (61, 'Host-Internal'), (62, 'CFTP'), (63, 'Local-Network'), (64, 'SAT-EXPAK'), (65, 'KRYPTOLAN'), (66, 'RVD'), (67, 'IPPC'), (68, 'Dist-File-System'), (69, 'SAT-MON'), (70, 'VISA'), (71, 'IPCU'), (72, 'CPNX'), (73, 'CPHB'), (74, 'WSN'), (75, 'PVP'), (76, 'BR-SAT-MON'), (77, 'SUN-ND'), (78, 'WB-MON'), (79, 'WB-EXPAK'), (80, 'ISO-IP'), (81, 'VMTP'), (82, 'SECURE-VMTP'), (83, 'VINES'), (84, 'TTP/IPTM'), (85, 'NSFNET-IGP'), (86, 'DGP'), (87, 'TCF'), (88, 'EIGRP'), (89, 'OSPF'), (90, 'Sprite-RPC'), (91, 'LARP'), (92, 'MTP'), (93, 'AX.25'), (94, 'OSKA'), (95, 'MICP'), (96, 'SCC-SP'), (97, 'ETHERIP'), (98, 'ENCAP'), (99, 'Private-Encr'), (100, 'GMTP'), (101, 'IFMP'), (102, 'PNNI'), (103, 'PIM'), (104, 'ARIS'), (105, 'SCPS'), (106, 'QNX'), (107, 'Active-Net'), (108, 'IPComp'), (109, 'SNP'), (110, 'Compaq-Peer'), (111, 'IPX-in-IP'), (112, 'VRRP'), (113, 'PGM'), (114, '0-hop'), (115, 'L2TP'), (116, 'DDX'), (117, 'IATP'), (118, 'STP'), (119, 'SRP'), (120, 'UTI'), (121, 'SMP'), (122, 'SM'), (123, 'PTP'), (124, 'IS-IS over IPv4'), (125, 'FIRE'), (126, 'CRTP'), (127, 'CRUDP'), (128, 'SSCOPMCE'), (129, 'IPLT'), (130, 'SPS'), (131, 'PIPE'), (132, 'SCTP'), (133, 'FC'), (134, 'RSVP-E2E-IGN'), (135, 'Mobility-Hdr'), (136, 'UDPLite'), (137, 'MPLS-in-IP'), (138, 'manet'), (139, 'HIP'), (140, 'Shim6'), (141, 'WESP'), (142, 'ROHC'), (143, 'Ethernet'), (144, 'AGGFRAG'), (145, 'NSH'), (146, 'Homa'), (147, 'BIT-EMU');

CREATE TABLE IF NOT EXISTS net_monitor.priority_source
(
    `code` UInt8,
    `label` String
)
ENGINE = MergeTree
ORDER BY code;

TRUNCATE TABLE net_monitor.priority_source;
INSERT INTO net_monitor.priority_source VALUES
    (0, 'Best Effort'), (1, 'Priority'), (2, 'Immediate'), (3, 'Flash'), (4, 'Flash Override'), (5, 'Critical'), (6, 'Internetwork Control'), (7, 'Network Control');

CREATE TABLE IF NOT EXISTS net_monitor.ecn_source
(
    `code` UInt8,
    `label` String
)
ENGINE = MergeTree
ORDER BY code;

TRUNCATE TABLE net_monitor.ecn_source;
INSERT INTO net_monitor.ecn_source VALUES
    (0, 'Not-ECT'), (1, 'ECN Capable'), (2, 'ECN Capable'), (3, 'Congestion');


--User and grants for dictionaries
CREATE USER IF NOT EXISTS dict_reader IDENTIFIED WITH no_password HOST LOCAL;
GRANT SELECT ON net_monitor.protocol_source TO dict_reader;
GRANT SELECT ON net_monitor.priority_source TO dict_reader;
GRANT SELECT ON net_monitor.ecn_source TO dict_reader;


--Dictionaries
CREATE DICTIONARY IF NOT EXISTS net_monitor.protocol_dict
(
    `id` UInt8,
    `label` String
)
PRIMARY KEY id
SOURCE(CLICKHOUSE(USER 'dict_reader' TABLE 'protocol_source' DB 'net_monitor'))
LAYOUT(HASHED())
LIFETIME(300);


CREATE DICTIONARY IF NOT EXISTS net_monitor.priority_dict
(
    `code` UInt8,
    `label` String
)
PRIMARY KEY code
SOURCE(CLICKHOUSE(USER 'dict_reader' TABLE 'priority_source' DB 'net_monitor'))
LAYOUT(FLAT())
LIFETIME(300);

CREATE DICTIONARY IF NOT EXISTS net_monitor.ecn_dict
(
    `code` UInt8,
    `label` String
)
PRIMARY KEY code
SOURCE(CLICKHOUSE(USER 'dict_reader' TABLE 'ecn_source' DB 'net_monitor'))
LAYOUT(FLAT())
LIFETIME(300);





-- Materialized views
CREATE MATERIALIZED VIEW IF NOT EXISTS net_monitor.flows_mv TO net_monitor.flows 
AS WITH
    [
        '::ffff:10.0.0.0/104',
        '::ffff:172.16.0.0/108',
        '::ffff:192.168.0.0/112',
        '::ffff:169.254.0.0/112',
        '::ffff:127.0.0.0/104',
        '::ffff:0.0.0.0/128',
        '::ffff:224.0.0.0/100',
        '::ffff:255.255.255.255/128',
        'fc00::/7',
        'fe80::/10',
        '::1/128',
        '::/128',
        'ff00::/8'
    ] AS local_ranges,
    arrayExists(r -> isIPAddressInRange(toString(srcip), r), local_ranges) AS src_is_local,
    arrayExists(r -> isIPAddressInRange(toString(dstip), r), local_ranges) AS dst_is_local
SELECT
    'exporter-1' AS device,
    vlanId,
    srcMacAddress,
    srcip,
    dstip,
    srcport,
    dstport,
    tcpflags,
    if(protocol = 6,
    trimRight(concat(
        if(bitAnd(tcpflags, 32) != 0, 'URG ', '. '),
        if(bitAnd(tcpflags, 16) != 0, 'ACK ', '. '),
        if(bitAnd(tcpflags, 8) != 0, 'PSH ', '. '),
        if(bitAnd(tcpflags, 4) != 0, 'RST ', '. '),
        if(bitAnd(tcpflags, 2) != 0, 'SYN ', '. '),
        if(bitAnd(tcpflags, 1) != 0, 'FIN', '.')
    )),
    '') AS tcpflags_str,
    bytes,
    packets,
    toDateTime(flowstart) AS flowstart,
    toDateTime(flowend) AS flowend,
    ipClassOfService,
    dictGet('net_monitor.priority_dict', 'label', toUInt8(bitShiftRight(ipClassOfService, 5))) AS priority,
    dictGet('net_monitor.ecn_dict', 'label', toUInt8(bitAnd(ipClassOfService, 3))) AS ecn,
    protocol,
    dictGetOrDefault('net_monitor.protocol_dict', 'label', protocol, toString(protocol)) AS protocol_name,
    multiIf(
        src_is_local AND dst_is_local, 'Internal',
        src_is_local, 'Outbound',
        dst_is_local, 'Inbound',
        'External'
    ) AS direction,
    if(src_is_local AND dst_is_local, 1, 0) AS is_internal
FROM net_monitor.flows_raw;