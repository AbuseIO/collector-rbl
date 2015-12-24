<?php

namespace AbuseIO\Collectors;

use Validator;
use AbuseIO\Models\Ticket;

class Rbl extends Collector
{
    /**
     * The allowed modes of operation of the scanner with a setting if they required validations
     *
     * @var array
     */
    protected $allowedModes = [
        'asns'          => true,
        'netblocks'     => true,
        'ipaddresses'   => true,
        'tickets'       => false,
    ];

    /**
     * The allowed methods of operation of the scanner with a setting if they required validations
     *
     * @var array
     */
    protected $allowedMethods = [
        'dns'           => false,
        'file'          => true,
    ];

    /**
     * The validations for each mode
     *
     * @var array
     */
    protected $rulesConfig = [
        'asns'          => 'required|string',
        'netblocks'     => 'required|string',
        'ipaddresses'   => 'required|string',
        'tickets'       => 'required|string',
    ];

    /**
     * The validations for each feed
     *
     * @var array
     */
    protected $rulesFeed = [
        'feedname'      => 'required|string',
        'name'          => 'required|string',
        'class'         => 'required|abuseclass',
        'type'          => 'required|abusetype',
        'enabled'       => 'required|boolean',
        'fields'        => 'sometimes|array',
        'filters'       => 'sometimes|array',
        'information'   => 'sometimes|array',
        'method'        => 'required|string',
        'zonefile'      => 'sometimes|isfile',
    ];

    /**
     * Create a new Abusehub instance
     *
     */
    public function __construct()
    {
        // Call the parent constructor to initialize some basics
        parent::__construct($this);
    }

    /**
     * Parse attachments
     * TODO: extend validations for each mode
     * TODO: actually do scanning in the case/switch method
     *
     * @return array    Returns array with failed or success data
     *                  (See collector-common/src/Collector.php) for more info.
     */
    public function parse()
    {
        /*
         * Preflight validations
         */
        $modes = array_change_key_case(config("{$this->configBase}.collector.modes"), CASE_LOWER);
        if (empty($modes) || !is_array($modes)) {
            return $this->failed('No mode of operation configured, or mode config invalid');
        }

        $feeds = array_change_key_case(config("{$this->configBase}.feeds"), CASE_LOWER);
        if (empty($feeds) || !is_array($feeds)) {
            return $this->failed('No RBL feeds configured, or feed config invalid');
        }

        foreach ($feeds as $feedName => $feedConfig) {
            $validator = Validator::make(
                array_merge($feedConfig, ['feedname' => $feedName]),
                $this->rulesFeed
            );

            if ($validator->fails()) {
                return $this->failed(implode(' ', $validator->messages()->all()));
            }
        }

        /*
         * For each configured mode kick of a scanning process.
         * Todo: Look into multithreading this in DNS mode
         */
        foreach($modes as $mode) {
            if(!array_key_exists($mode, $this->allowedModes)) {
                return $this->failed("Configuration error detected. Mode {$mode} is not an option");
            }

            if($this->allowedModes[$mode]) {
                $config = config("{$this->configBase}.collector.{$mode}");

                if (empty($config) || !is_array($config)) {
                    return $this->failed(
                        "Configuration error detected. The settings for mode {$mode} is empty or not an array"
                    );
                }

                foreach ($config as $configElement) {
                    $validator = Validator::make(
                        [ $mode => $configElement ],
                        [ $mode => $this->rulesConfig[$mode] ]
                    );

                    if ($validator->fails()) {
                        return $this->failed(implode(' ', $validator->messages()->all()));
                    }
                }

            } else {
                continue;
            }

            switch($mode) {
                case "asns":
                    $this->scanAsn($config);
                    break;
                case "netblocks":
                    $this->scanNetblock($config);
                    break;
                case "ipaddresses":
                    $this->scanAddresses($config);
                    break;
                case "tickets":
                    $this->scanTickets();
                    break;
            }

        }

        return $this->success();
    }

    /*
     * Retrieve a list of netblocks based on the ASN and kick off scanNetblock for each
     * @internal: keep a record of netblocks done, to prevent duplicate work
     */
    private function scanAsn($asns) {
        $netblocks = [];

        foreach ($asns as $asn) {
            $dns = dns_get_record("as{$asn}.ascc.dnsbl.bit.nl", DNS_TXT);
            foreach($dns as $key => $entry) {
                if (!in_array($entry, $netblocks)) {
                    $this->scanNetblock($netblocks);

                    $netblocks[] = $entry['txt'];
                }
            }
        }

        return true;
    }

    /*
     * Retrieve a list of addresses based on a netblock and kick off scanAddress
     */
    private function scanNetblock($netblocks) {

        foreach ($netblocks as $netblock) {
            $range = $this->getAddressRange($netblock);
            $rangeAddresses = [];

            for($pos = $range['begin']; $pos <= $range['end']; $pos++) {
                $ip = long2ip($pos);
                if(substr($ip, - 2) !== '.0' && substr($ip, - 4) !== '.255') {
                    $rangeAddresses[] = $ip;
                }
            }

            $this->scanAddresses($rangeAddresses);
        }
    }

    /*
     * Build array with first and last address of a netblock based on CIDR
     */
    private function getAddressRange($netblock) {
        $t = explode('/', $netblock);
        $addr = $t[0];
        $cidr = $t[1];

        $corr=( pow(2, 32) - 1)-(pow(2, 32 - $cidr) - 1 );
        $first=ip2long($addr) & ($corr);
        $length=pow(2, 32 - $cidr) - 1;

        return [
            'begin'  => $first,
            'end'   => $first + $length,
        ];

    }
    /*
     * Use array with addresses and kick of scanAddress
     */
    private function scanAddresses($addresses) {
        foreach ($addresses as $address) {
            $this->scanAddress($address);
        }
    }

    /*
     * Retrieve a list of addresses based on open tickets and kick off scanAddress
     */
    private function scanTickets() {
        $tickets = Ticket::where('status_id', '!=', '2')->get();

        foreach ($tickets as $ticket) {
            $this->scanAddress($ticket->ip);
        }
    }

    /*
     * Scan the address using a DNS request
     */
    private function scanAddress($address) {
        if (!filter_var($address, FILTER_VALIDATE_IP) === false) {
            $addressReverse = implode('.', array_reverse(preg_split('/\./', $address)));

            // TODO move into config
            $rbls = [
                ['zone' => 'xbl.spamhaus.org']
            ];
            foreach ($rbls as $rbl) {
                $lookup = $addressReverse . '.' . $rbl['zone'] . '.';

                if ($result = gethostbyname($lookup)) {
                    if ($result != $lookup) {
                        // TODO add event;
                    }
                }
            }
        }

        die();
    }
}
