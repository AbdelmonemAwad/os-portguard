<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Abdelmonem Awad <eg2@live.com>
 */

namespace OPNsense\PortGuard\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'portguard';
    protected static $internalModelClass = '\OPNsense\PortGuard\PortGuard';

    public function searchDeviceAction()
    {
        return $this->searchBase('devices.device', ['enabled', 'mac', 'description'], 'mac');
    }

    public function getDeviceAction($uuid = null)
    {
        return $this->getBase('device', 'devices.device', $uuid);
    }

    public function addDeviceAction()
    {
        return $this->addBase('device', 'devices.device');
    }

    public function setDeviceAction($uuid)
    {
        return $this->setBase('device', 'devices.device', $uuid);
    }

    public function delDeviceAction($uuid)
    {
        return $this->delBase('devices.device', $uuid);
    }

    public function toggleDeviceAction($uuid, $enabled = null)
    {
        return $this->toggleBase('devices.device', $uuid, $enabled);
    }
}
