<?php

return [
    'collector' => [
        'name'          => 'Rbl',
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
