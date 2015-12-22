<?php

return [
    'collector' => [
        'name'          => 'Rbl',
        'description'   => 'Collects data from RBL lists to generate events',
        'enabled'       => true,
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
