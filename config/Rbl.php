<?php
/*
 * Allowed modes: You can combine these options, as long as you meet the config requirements of each option
 *
 * asn : Scan a list of ASN's. The list will be collected by BIT's ASCC Database through a DNS query
 * netblocks : Scans a list of netblocks, based on a CIDR annotated list of netblocks
 * ipaddresses : Scans a list of single IP addresses, based on a fixed/valid IP without CIDR
 * tickets : Scans all the single IP addresses, based on the open tickets of the AbuseIO system
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
            '12859'
        ],
        'netblocks'     => [
            //
        ],
        'ipaddresses'   => [
            //
        ],

    ],

    'feeds' => [
        'Default' => [
            'class'     => 'test',
            'type'      => 'Abuse',
            'enabled'   => true,
            'fields'    => [
                'test'  => 'test',
            ],
        ],
    ],
];
