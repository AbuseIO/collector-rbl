<?php

namespace AbuseIO\Collectors;

use Validator;

class Rbl extends Collector
{
    /**
     * The allowed modes of operation of the scanner
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
     * The validations for each mode
     *
     * @var array
     */
    protected $validate = [
        'asns'          => 'required|string',
        'netblocks'     => 'required|string',
        'ipaddresses'   => 'required|string',
        'tickets'       => 'required|string',
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
                        [
                            $mode => $configElement
                        ],
                        [
                            $mode => $this->validate[$mode]
                        ]
                    );

                    if ($validator->fails()) {
                        $messages = $validator->messages();

                        $message = '';
                        foreach ($messages->all() as $messagePart) {
                            $message .= $messagePart;
                        }

                        return $this->failed($message);
                    }
                }
            }
        }

        switch($modes) {
            case "asns":

                break;
            case "netblocks":

                break;
            case "ipaddresses":

                break;
            case "tickets":

                break;
        }

        return $this->success();
    }
}
