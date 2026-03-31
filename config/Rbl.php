<?php
/*
 * Allowed modes: You can combine these options, as long as you meet the config requirements of each option
 *
 * asn          : Scan a list of ASN's. The list will be collected by BIT's ASCC Database through a DNS query
 * netblocks    : Scans a list of netblocks, based on a CIDR annotated list of netblocks
 * ipaddresses  : Scans a list of single IP addresses, based on a fixed/valid IP without CIDR
 * tickets      : Scans all the single IP addresses, based on the open tickets of the AbuseIO system
 *
 * Please note that if you select ASN or a large number of netblocks the collector can take a VERY long time with
 * the default method DNS. If you have Zonefiles and change the method to file you can speed up the lookups considerably
 * however getting these zonefiles require a subscription in most cases.
 *
 * Also be aware that if you do heavy scanning, the RBL in question might start blocking your requests as you need a
 * commercial / subscription to do such bulk queries. Sadly most RBL's dont have reporting to ASN's in places.
 *
 */
return [
    'collector' => [
        'name'          => 'RBL Scanner',
        'description'   => 'Collects data from RBL lists to generate events',
        'enabled'       => true,

        /*
         * Mode setting
         */
        'modes'          => [
            //'asns',
            //'netblocks',
            //'ipaddresses',
            'tickets',
        ],

        /*
         * Mode configurations
         */
        'asns'          => [
            //
        ],
        'netblocks'     => [
            //
        ],
        'ipaddresses'   => [
            //
        ],

    ],

    /*
     * Method can be either 'dns' or 'file'. If set to file, the zonefile must be set to the RBLDNSD file
     */
    'feeds' => [
        'Spamhaus' => [
            'zone'         => 'zen.spamhaus.org',
            'class'        => 'RBL_LISTED',
            'type'         => 'ABUSE',
            'enabled'      => true,
            'fields'       => [
                //
            ],
            'filters'      => [
                //
            ],
            'information'  => [
                'delisting url' => 'https://www.spamhaus.org/lookup/',
            ],
            'codes'        => [
                '127.0.0.2'     => 'SBL Listing - Contains: Direct UBE sources, spam operations & spam service',
                '127.0.0.3'     => 'CSS Listing - Contains: Direct snowshoe spam sources detected via automation',
                '127.0.0.4'     => 'XBL Listing - Contains: CBL (3rd party exploits such as proxies, trojans, etc.)',
                '127.0.0.5'     => 'XBL Listing - Contains: CBL (3rd party exploits such as proxies, trojans, etc.)',
                '127.0.0.6'     => 'XBL Listing - Contains: CBL (3rd party exploits such as proxies, trojans, etc.)',
                '127.0.0.7'     => 'XBL Listing - Contains: CBL (3rd party exploits such as proxies, trojans, etc.)',
                '127.0.0.10'    =>
                    'PBL Listing - Contains: End-user Non-MTA IP addresses set by ISP outbound mail policy',
                '127.0.0.11'    =>
                    'PBL Listing - Contains: End-user Non-MTA IP addresses set by ISP outbound mail policy',
                'default'       => 'SPAM Sending host'
            ],
            'ignore_codes' => [
                //
            ],
            'method'       => 'dns',
            'zonefile'     => '',
        ],
        'Spamcop' => [
            'zone'         => 'bl.spamcop.net',
            'class'        => 'RBL_LISTED',
            'type'         => 'ABUSE',
            'enabled'      => true,
            'fields'       => [
                //
            ],
            'filters'      => [
                //
            ],
            'information'  => [
                'delisting url' => 'https://www.spamcop.net/bl.shtml',
            ],
            'codes'        => [
                '127.0.0.2'     => 'SCBL Listing - Contains: End-user reports, SPAM traps and other detection types',
                'default'       => 'SPAM Sending host'
            ],
            'ignore_codes' => [
                //
            ],
            'method'       => 'dns',
            'zonefile'     => '',
        ],
    ],
];
